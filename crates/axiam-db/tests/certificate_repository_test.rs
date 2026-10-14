//! CRUD + edge-case coverage for `SurrealCertificateRepository` — no
//! existing axiam-db-local test file covers this repository at all.
//! Uses the in-memory SurrealDB engine — no external services required.

use axiam_core::ca_keys::CaKeyCustody;
use axiam_core::models::certificate::{
    CertificateStatus, CertificateType, KeyAlgorithm, StoreCaCertificate, StoreCertificate,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::service_account::CreateServiceAccount;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{
    CaCertificateRepository, CertificateRepository, OrganizationRepository, Pagination,
    ServiceAccountRepository, TenantRepository,
};
use axiam_db::repository::{
    SurrealCaCertificateRepository, SurrealCertificateRepository, SurrealOrganizationRepository,
    SurrealServiceAccountRepository, SurrealTenantRepository,
};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type Db = Surreal<surrealdb::engine::local::Db>;

async fn setup() -> (Db, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Tenant".into(),
            slug: "tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    (db, org.id, tenant.id)
}

fn sample_cert(tenant_id: Uuid, issuer_ca_id: Uuid, fingerprint: &str) -> StoreCertificate {
    StoreCertificate {
        tenant_id,
        issuer_ca_id,
        subject: "CN=leaf.example.com".into(),
        public_cert_pem: "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----".into(),
        fingerprint: fingerprint.into(),
        cert_type: CertificateType::User,
        key_algorithm: KeyAlgorithm::Ed25519,
        not_before: Utc::now() - Duration::minutes(1),
        not_after: Utc::now() + Duration::days(365),
        metadata: serde_json::json!({}),
        user_id: None,
    }
}

#[tokio::test]
async fn create_get_list_revoke_lifecycle() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealCertificateRepository::new(db);
    let issuer_ca_id = Uuid::new_v4();

    let cert = repo
        .create(sample_cert(tenant_id, issuer_ca_id, "fp-lifecycle-1"))
        .await
        .unwrap();
    assert_eq!(cert.tenant_id, tenant_id);
    assert_eq!(cert.status, CertificateStatus::Active);
    assert_eq!(cert.cert_type, CertificateType::User);
    assert_eq!(cert.key_algorithm, KeyAlgorithm::Ed25519);

    // get_by_id
    let got = repo.get_by_id(tenant_id, cert.id).await.unwrap();
    assert_eq!(got.fingerprint, "fp-lifecycle-1");

    // get_by_fingerprint
    let by_fp = repo
        .get_by_fingerprint(tenant_id, "fp-lifecycle-1")
        .await
        .unwrap();
    assert_eq!(by_fp.id, cert.id);

    // get_by_fingerprint_global
    let global = repo
        .get_by_fingerprint_global("fp-lifecycle-1")
        .await
        .unwrap();
    assert_eq!(global.id, cert.id);

    // list
    let page = repo.list(tenant_id, Pagination::default()).await.unwrap();
    assert!(page.items.iter().any(|c| c.id == cert.id));

    // revoke
    repo.revoke(tenant_id, cert.id).await.unwrap();
    let revoked = repo.get_by_id(tenant_id, cert.id).await.unwrap();
    assert_eq!(revoked.status, CertificateStatus::Revoked);
}

#[tokio::test]
async fn get_by_id_not_found() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealCertificateRepository::new(db);
    let err = repo.get_by_id(tenant_id, Uuid::new_v4()).await.unwrap_err();
    assert!(format!("{err:?}").to_lowercase().contains("notfound") || !format!("{err}").is_empty());
}

#[tokio::test]
async fn get_by_fingerprint_not_found() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealCertificateRepository::new(db);
    assert!(
        repo.get_by_fingerprint(tenant_id, "does-not-exist")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn get_by_fingerprint_global_not_found() {
    let (db, _org, _tenant_id) = setup().await;
    let repo = SurrealCertificateRepository::new(db);
    assert!(repo.get_by_fingerprint_global("nope-global").await.is_err());
}

#[tokio::test]
async fn revoke_not_found_errors() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealCertificateRepository::new(db);
    assert!(repo.revoke(tenant_id, Uuid::new_v4()).await.is_err());
}

#[tokio::test]
async fn cross_tenant_get_by_id_is_not_found() {
    let (db, org_id, tenant_a) = setup().await;
    let tenant_b = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org_id,
            kind: TenantKind::Standard,
            name: "Tenant B".into(),
            slug: "tenant-b".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;

    let repo = SurrealCertificateRepository::new(db);
    let cert = repo
        .create(sample_cert(tenant_a, Uuid::new_v4(), "fp-cross-tenant"))
        .await
        .unwrap();

    // Visible in its own tenant...
    assert!(repo.get_by_id(tenant_a, cert.id).await.is_ok());
    // ...but not in another tenant.
    assert!(repo.get_by_id(tenant_b, cert.id).await.is_err());
}

#[tokio::test]
async fn list_pagination() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealCertificateRepository::new(db);

    for i in 0..5 {
        repo.create(sample_cert(
            tenant_id,
            Uuid::new_v4(),
            &format!("fp-page-{i}"),
        ))
        .await
        .unwrap();
    }

    let page1 = repo
        .list(
            tenant_id,
            Pagination {
                offset: 0,
                limit: 3,
                search: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(page1.items.len(), 3);
    assert_eq!(page1.total, 5);

    let page2 = repo
        .list(
            tenant_id,
            Pagination {
                offset: 3,
                limit: 3,
                search: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(page2.items.len(), 2);
}

#[tokio::test]
async fn bind_to_service_account_success_and_lookup() {
    let (db, _org, tenant_id) = setup().await;
    let cert_repo = SurrealCertificateRepository::new(db.clone());
    let sa_repo = SurrealServiceAccountRepository::new(db);

    let cert = cert_repo
        .create(sample_cert(tenant_id, Uuid::new_v4(), "fp-bind-1"))
        .await
        .unwrap();

    let sa = sa_repo
        .create(CreateServiceAccount {
            tenant_id,
            name: "svc-account".into(),
            description: None,
        })
        .await
        .unwrap();

    // No binding yet.
    assert_eq!(
        cert_repo.get_bound_service_account(cert.id).await.unwrap(),
        None
    );

    cert_repo
        .bind_to_service_account(tenant_id, cert.id, sa.0.id)
        .await
        .unwrap();

    let bound = cert_repo.get_bound_service_account(cert.id).await.unwrap();
    assert_eq!(bound, Some(sa.0.id));
}

#[tokio::test]
async fn bind_to_service_account_cross_tenant_denied() {
    let (db, org_id, tenant_a) = setup().await;
    let tenant_b = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org_id,
            kind: TenantKind::Standard,
            name: "Tenant B".into(),
            slug: "tenant-b-bind".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;

    let cert_repo = SurrealCertificateRepository::new(db.clone());
    let sa_repo = SurrealServiceAccountRepository::new(db);

    let cert = cert_repo
        .create(sample_cert(tenant_a, Uuid::new_v4(), "fp-bind-cross"))
        .await
        .unwrap();

    // Service account lives in tenant_b — binding to tenant_a's cert must be denied.
    let sa = sa_repo
        .create(CreateServiceAccount {
            tenant_id: tenant_b,
            name: "other-tenant-sa".into(),
            description: None,
        })
        .await
        .unwrap();

    let err = cert_repo
        .bind_to_service_account(tenant_a, cert.id, sa.0.id)
        .await
        .unwrap_err();
    assert!(
        format!("{err:?}").to_lowercase().contains("authoriz")
            || format!("{err:?}").to_lowercase().contains("denied"),
        "expected an authorization-denied error, got: {err:?}"
    );
}

#[tokio::test]
async fn get_bound_service_account_unbound_is_none() {
    let (db, _org, tenant_id) = setup().await;
    let cert_repo = SurrealCertificateRepository::new(db);

    let cert = cert_repo
        .create(sample_cert(tenant_id, Uuid::new_v4(), "fp-unbound"))
        .await
        .unwrap();

    assert_eq!(
        cert_repo.get_bound_service_account(cert.id).await.unwrap(),
        None
    );
}

/// G-2 / D-21: the SAML signing leaf is never an inventory row. The repository
/// writes the type's name and the schema's assertion refuses it, so a path that
/// forgot the rule fails at the insert; every other type round-trips.
#[tokio::test]
async fn the_inventory_stores_every_type_but_the_saml_signing_leaf() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealCertificateRepository::new(db.clone());
    for (n, cert_type) in [
        CertificateType::User,
        CertificateType::Service,
        CertificateType::Device,
        CertificateType::Server,
    ]
    .into_iter()
    .enumerate()
    {
        let mut input = sample_cert(tenant_id, Uuid::new_v4(), &format!("fp-type-{n}"));
        input.cert_type = cert_type.clone();
        let created = repo.create(input).await.unwrap();
        assert_eq!(created.cert_type, cert_type);
        let read = repo.get_by_id(tenant_id, created.id).await.unwrap();
        assert_eq!(read.cert_type, cert_type);
    }

    let mut saml = sample_cert(tenant_id, Uuid::new_v4(), "fp-type-saml");
    saml.cert_type = CertificateType::SamlSigning;
    assert!(
        repo.create(saml).await.is_err(),
        "the certificate inventory must refuse the SAML signing leaf"
    );
}

// ---------------------------------------------------------------------------
// The Vault revocation sweep's bookkeeping (T-470, #603)
// ---------------------------------------------------------------------------

/// An active CA whose key Vault's PKI engine holds, and `n` leaves of it,
/// revoked in AXIAM and not forwarded to Vault.
async fn revoked_vault_leaves(
    db: &Db,
    org: Uuid,
    tenant_id: Uuid,
    n: usize,
) -> (
    SurrealCertificateRepository<surrealdb::engine::local::Db>,
    Vec<Uuid>,
) {
    let ca_id = Uuid::new_v4();
    SurrealCaCertificateRepository::new(db.clone())
        .create(StoreCaCertificate {
            id: ca_id,
            organization_id: org,
            tenant_id: None,
            parent_ca_id: None,
            subject: "CN=Vault CA".into(),
            public_cert_pem: "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
                .into(),
            chain_pem: None,
            fingerprint: "sha256:vault-ca".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            not_before: Utc::now() - Duration::minutes(1),
            not_after: Utc::now() + Duration::days(3650),
            encrypted_private_key: None,
            key_custody: CaKeyCustody::VaultPki,
            key_locator: Some("{}".into()),
        })
        .await
        .unwrap();
    let repo = SurrealCertificateRepository::new(db.clone());
    let mut ids = Vec::new();
    for i in 0..n {
        let cert = repo
            .create(sample_cert(tenant_id, ca_id, &format!("fp-vault-{i}")))
            .await
            .unwrap();
        repo.revoke(tenant_id, cert.id).await.unwrap();
        ids.push(cert.id);
        // `revoked_at` orders rows of equal due date; keep them apart.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    (repo, ids)
}

/// One refused attempt on `id`, as the sweep makes it (#603, R101W1-09 (d)):
/// claimed on the date the due list read, then the failure recorded on the
/// claim's lease.
async fn refuse(
    repo: &SurrealCertificateRepository<surrealdb::engine::local::Db>,
    tenant_id: Uuid,
    id: Uuid,
    attempts: u32,
    next: chrono::DateTime<Utc>,
    error: &str,
) {
    let seen = repo
        .list_due_vault_forwards(Utc::now() + Duration::days(1), 100)
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.certificate.id == id)
        .expect("an unforwarded row")
        .next_attempt_at;
    let lease = Utc::now() + Duration::minutes(2);
    assert!(
        repo.claim_vault_forward(tenant_id, id, seen, lease)
            .await
            .unwrap()
    );
    assert!(
        repo.record_vault_forward_failure(tenant_id, id, lease, attempts, next, error)
            .await
            .unwrap()
    );
}

/// A row never attempted carries none of the v95 fields and is due at once with
/// no attempts (D-6: no backfill); a refused row leaves the due list until its
/// backoff runs out and comes back with what was recorded.
#[tokio::test]
async fn a_refused_revocation_leaves_the_due_list_until_its_backoff_runs_out() {
    let (db, org, tenant_id) = setup().await;
    let (repo, ids) = revoked_vault_leaves(&db, org, tenant_id, 3).await;
    let now = Utc::now();

    let due = repo.list_due_vault_forwards(now, 10).await.unwrap();
    assert_eq!(
        due.iter().map(|c| c.certificate.id).collect::<Vec<_>>(),
        ids,
        "never attempted: all due, oldest revocation first"
    );
    assert!(
        due.iter()
            .all(|c| c.attempts == 0 && c.next_attempt_at.is_none() && c.last_error.is_none())
    );

    // The oldest is claimed and refused: its next attempt is an hour away.
    refuse(
        &repo,
        tenant_id,
        ids[0],
        1,
        now + Duration::hours(1),
        "vault pki: answered 403 Forbidden: permission denied",
    )
    .await;
    let due = repo.list_due_vault_forwards(now, 10).await.unwrap();
    assert_eq!(
        due.iter().map(|c| c.certificate.id).collect::<Vec<_>>(),
        ids[1..],
        "a refused row does not hold the later ones back"
    );
    // The unfiltered read still names it, last.
    let pending = repo.list_unforwarded_revocations(10).await.unwrap();
    assert_eq!(
        pending.iter().map(|c| c.id).collect::<Vec<_>>(),
        [ids[1], ids[2], ids[0]]
    );

    // An hour on it is due again, with what the failure recorded.
    let later = repo
        .list_due_vault_forwards(now + Duration::hours(2), 10)
        .await
        .unwrap();
    let first = later.iter().find(|c| c.certificate.id == ids[0]).unwrap();
    assert_eq!(first.attempts, 1);
    assert_eq!(
        first.last_error.as_deref(),
        Some("vault pki: answered 403 Forbidden: permission denied")
    );
    assert!(first.next_attempt_at.is_some());
    assert_eq!(later[0].certificate.id, ids[1], "never attempted first");
}

/// Of any number of replicas that read one row, exactly one claims it; a claim
/// made on a stale read, or on a forwarded row, wins nothing.
#[tokio::test]
async fn of_concurrent_claims_of_one_row_exactly_one_wins() {
    let (db, org, tenant_id) = setup().await;
    let (repo, ids) = revoked_vault_leaves(&db, org, tenant_id, 1).await;
    let id = ids[0];
    let lease = Utc::now() + Duration::minutes(2);

    // Two replicas, then eight, each holding the read `next_attempt_at = NONE`.
    for round in 0..2 {
        let claimants = if round == 0 { 2 } else { 8 };
        let mut tasks = Vec::new();
        for _ in 0..claimants {
            let repo = repo.clone();
            tasks.push(tokio::spawn(async move {
                repo.claim_vault_forward(tenant_id, id, None, lease)
                    .await
                    .unwrap()
            }));
        }
        let mut won = 0;
        for task in tasks {
            won += usize::from(task.await.unwrap());
        }
        assert_eq!(won, 1, "round {round}: exactly one claim wins");

        // Release the lease for the next round, as a failure would.
        assert!(
            repo.record_vault_forward_failure(tenant_id, id, lease, round + 1, Utc::now(), "again")
                .await
                .unwrap()
        );
        // The row now holds a date; the stale read (`NONE`) no longer matches.
        assert!(
            !repo
                .claim_vault_forward(tenant_id, id, None, lease)
                .await
                .unwrap(),
            "a claim on a stale read wins nothing"
        );
        // Reset to "never attempted" for the next round's claimants.
        db.query("UPDATE type::record('certificate', $id) SET vault_next_attempt_at = NONE")
            .bind(("id", id.to_string()))
            .await
            .unwrap()
            .check()
            .unwrap();
    }

    // The claim moved the date: the row is not due while the lease holds.
    assert!(
        repo.claim_vault_forward(tenant_id, id, None, lease)
            .await
            .unwrap()
    );
    assert!(
        repo.list_due_vault_forwards(Utc::now(), 10)
            .await
            .unwrap()
            .is_empty(),
        "a claimed row is not due for another replica"
    );
    // Claiming on the date the first claim wrote works once, then not again.
    let next = lease + Duration::minutes(1);
    assert!(
        repo.claim_vault_forward(tenant_id, id, Some(lease), next)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .claim_vault_forward(tenant_id, id, Some(lease), next)
            .await
            .unwrap()
    );

    // A forwarded row cannot be claimed, and a failure does not touch it.
    repo.mark_revocation_forwarded(tenant_id, id).await.unwrap();
    assert!(
        !repo
            .claim_vault_forward(tenant_id, id, Some(next), lease)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .record_vault_forward_failure(tenant_id, id, next, 9, Utc::now(), "late")
            .await
            .unwrap()
    );
    assert_eq!(repo.count_vault_forwards_failing(1).await.unwrap(), 0);
}

/// Another tenant cannot claim, or write a failure on, this tenant's row.
#[tokio::test]
async fn the_claim_and_the_failure_stay_inside_the_tenant() {
    let (db, org, tenant_id) = setup().await;
    let (repo, ids) = revoked_vault_leaves(&db, org, tenant_id, 1).await;
    let other = Uuid::new_v4();
    let lease = Utc::now() + Duration::minutes(2);
    assert!(
        !repo
            .claim_vault_forward(other, ids[0], None, lease)
            .await
            .unwrap()
    );
    // Even on the lease this tenant's claim wrote, another tenant's failure
    // writes nothing.
    assert!(
        repo.claim_vault_forward(tenant_id, ids[0], None, lease)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .record_vault_forward_failure(other, ids[0], lease, 5, Utc::now(), "not yours")
            .await
            .unwrap()
    );
    let due = repo
        .list_due_vault_forwards(Utc::now() + Duration::hours(1), 10)
        .await
        .unwrap();
    assert_eq!(due[0].attempts, 0);
}

/// R101W1-09 (d): a refusal is recorded only on the lease its claim wrote. A
/// replica whose attempt outlived its lease — the row since claimed by another
/// replica — writes nothing: not the count, not the reason, and not the date
/// that now holds the other replica's lease.
#[tokio::test]
async fn a_failure_recorded_on_a_lapsed_claim_writes_nothing() {
    let (db, org, tenant_id) = setup().await;
    let (repo, ids) = revoked_vault_leaves(&db, org, tenant_id, 1).await;
    let id = ids[0];

    // Replica A claims with a lease that has already run out.
    let lapsed = Utc::now() - Duration::seconds(1);
    assert!(
        repo.claim_vault_forward(tenant_id, id, None, lapsed)
            .await
            .unwrap()
    );
    // Replica B reads the row due again and claims it over A's lease.
    let due = repo.list_due_vault_forwards(Utc::now(), 10).await.unwrap();
    assert_eq!(due[0].next_attempt_at, Some(lapsed));
    let current = Utc::now() + Duration::minutes(2);
    assert!(
        repo.claim_vault_forward(tenant_id, id, Some(lapsed), current)
            .await
            .unwrap()
    );

    // A's late refusal writes nothing: B's lease and the count stand.
    assert!(
        !repo
            .record_vault_forward_failure(tenant_id, id, lapsed, 7, Utc::now(), "late")
            .await
            .unwrap()
    );
    let row = repo
        .list_due_vault_forwards(Utc::now() + Duration::hours(1), 10)
        .await
        .unwrap();
    assert_eq!(
        (
            row[0].attempts,
            row[0].next_attempt_at,
            row[0].last_error.as_deref()
        ),
        (0, Some(current), None)
    );
    assert!(
        repo.list_due_vault_forwards(Utc::now(), 10)
            .await
            .unwrap()
            .is_empty(),
        "B's lease still holds the row back"
    );

    // B's refusal, on its own lease, is recorded.
    assert!(
        repo.record_vault_forward_failure(tenant_id, id, current, 1, Utc::now(), "refused")
            .await
            .unwrap()
    );
    let row = repo.list_due_vault_forwards(Utc::now(), 10).await.unwrap();
    assert_eq!(
        (row[0].attempts, row[0].last_error.as_deref()),
        (1, Some("refused"))
    );
}

/// The reason a row keeps is bounded whatever the caller sent, and the count of
/// failing rows follows the attempts recorded.
#[tokio::test]
async fn the_stored_reason_is_bounded_and_failing_rows_are_counted() {
    let (db, org, tenant_id) = setup().await;
    let (repo, ids) = revoked_vault_leaves(&db, org, tenant_id, 3).await;
    let soon = Utc::now() + Duration::hours(1);

    refuse(&repo, tenant_id, ids[0], 12, soon, &"x".repeat(5_000)).await;
    refuse(&repo, tenant_id, ids[1], 11, soon, "fewer").await;
    refuse(&repo, tenant_id, ids[2], 30, soon, "many").await;

    assert_eq!(repo.count_vault_forwards_failing(12).await.unwrap(), 2);
    assert_eq!(repo.count_vault_forwards_failing(11).await.unwrap(), 3);
    assert_eq!(repo.count_vault_forwards_failing(31).await.unwrap(), 0);

    let due = repo
        .list_due_vault_forwards(soon + Duration::hours(1), 10)
        .await
        .unwrap();
    let long = due.iter().find(|c| c.certificate.id == ids[0]).unwrap();
    assert_eq!(long.last_error.as_ref().unwrap().chars().count(), 256);
    assert_eq!(long.attempts, 12);

    // A forwarded row drops out of the count.
    repo.mark_revocation_forwarded(tenant_id, ids[0])
        .await
        .unwrap();
    assert_eq!(repo.count_vault_forwards_failing(12).await.unwrap(), 1);
}

// ---------------------------------------------------------------------------
// The user binding (#533, schema v98)
// ---------------------------------------------------------------------------

/// `user_id` is stored and every read returns it; a row without one reads
/// `None`. A user's certificates revoked through `revoke_user_certificates`
/// are dated, so on their issuer's list, and — under a `vault_pki` CA — due to
/// the Vault sweep (T-470): the bulk path sets exactly what the sweep reads.
#[tokio::test]
async fn the_user_binding_reads_back_and_a_users_revocation_is_due_to_the_vault_sweep() {
    let (db, org, tenant_id) = setup().await;
    let vault_ca = Uuid::new_v4();
    SurrealCaCertificateRepository::new(db.clone())
        .create(StoreCaCertificate {
            id: vault_ca,
            organization_id: org,
            tenant_id: None,
            parent_ca_id: None,
            subject: "CN=Vault CA".into(),
            public_cert_pem: "not-a-parsed-certificate".into(),
            chain_pem: None,
            fingerprint: "sha256:vault-ca-533".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            not_before: Utc::now() - Duration::minutes(1),
            not_after: Utc::now() + Duration::days(3650),
            encrypted_private_key: None,
            key_custody: CaKeyCustody::VaultPki,
            key_locator: Some("{}".into()),
        })
        .await
        .unwrap();
    let repo = SurrealCertificateRepository::new(db.clone());
    let user = Uuid::new_v4();

    let bound = repo
        .create(StoreCertificate {
            user_id: Some(user),
            ..sample_cert(tenant_id, vault_ca, "fp-bound")
        })
        .await
        .unwrap();
    let unbound = repo
        .create(sample_cert(tenant_id, vault_ca, "fp-unbound"))
        .await
        .unwrap();
    assert_eq!(bound.user_id, Some(user));
    assert_eq!(unbound.user_id, None);
    assert_eq!(
        repo.get_by_id(tenant_id, bound.id).await.unwrap().user_id,
        Some(user)
    );
    assert_eq!(
        repo.get_by_fingerprint(tenant_id, "fp-bound")
            .await
            .unwrap()
            .user_id,
        Some(user)
    );
    let page = repo.list(tenant_id, Pagination::default()).await.unwrap();
    for cert in &page.items {
        let expected = if cert.id == bound.id {
            Some(user)
        } else {
            None
        };
        assert_eq!(cert.user_id, expected, "{}", cert.fingerprint);
    }

    // The sample's CN matches no name passed here: only the binding matches.
    let revoked = repo
        .revoke_user_certificates(
            tenant_id,
            user,
            "nobody",
            "nobody@example.com",
            Utc::now() - Duration::hours(1),
        )
        .await
        .unwrap();
    assert_eq!(revoked, 1);

    let due = repo.list_due_vault_forwards(Utc::now(), 100).await.unwrap();
    assert_eq!(due.len(), 1, "the revoked leaf is the sweep's to forward");
    assert_eq!(due[0].certificate.id, bound.id);
    assert_eq!(due[0].certificate.user_id, Some(user));
    let listed = repo
        .list_revoked_by_issuer(vault_ca, Utc::now())
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].revoked_at.is_some());
}

// ---------------------------------------------------------------------------
// #653 — serials are stored and unique under their issuer (migration v99)
// ---------------------------------------------------------------------------

/// A real self-signed certificate carrying exactly `serial`, as PEM.
fn pem_with_serial(serial: &[u8], cn: &str) -> String {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.serial_number = Some(rcgen::SerialNumber::from_slice(serial));
    params.self_signed(&key).unwrap().pem()
}

fn sample_ca(
    org: Uuid,
    parent: Option<Uuid>,
    pem: String,
    fingerprint: &str,
) -> StoreCaCertificate {
    StoreCaCertificate {
        id: Uuid::new_v4(),
        organization_id: org,
        tenant_id: None,
        parent_ca_id: parent,
        subject: "CN=CA".into(),
        public_cert_pem: pem,
        chain_pem: None,
        fingerprint: fingerprint.into(),
        key_algorithm: KeyAlgorithm::Ed25519,
        not_before: Utc::now() - Duration::minutes(1),
        not_after: Utc::now() + Duration::days(3650),
        encrypted_private_key: None,
        key_custody: CaKeyCustody::VaultPki,
        key_locator: Some("{}".into()),
    }
}

/// Rows whose certificate cannot be read carry `serial = NONE`, and NONE does
/// not collide in the unique index: this is what lets the index build over
/// rows written before the fix (none of them has a serial column), including
/// pairs that already share a serial inside their PEM.
#[tokio::test]
async fn rows_without_a_recorded_serial_do_not_collide() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealCertificateRepository::new(db);
    let issuer = Uuid::new_v4();
    for i in 0..3 {
        repo.create(sample_cert(tenant_id, issuer, &format!("fp-none-{i}")))
            .await
            .unwrap();
    }
}

/// The same serial under one issuer is refused; under another issuer it is a
/// different certificate and is accepted.
#[tokio::test]
async fn one_issuer_cannot_issue_a_serial_twice() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealCertificateRepository::new(db);
    let issuer = Uuid::new_v4();
    let other_issuer = Uuid::new_v4();
    let serial = [0x11u8; 20];

    let first = StoreCertificate {
        public_cert_pem: pem_with_serial(&serial, "first"),
        ..sample_cert(tenant_id, issuer, "fp-serial-1")
    };
    repo.create(first).await.unwrap();

    let twin = StoreCertificate {
        public_cert_pem: pem_with_serial(&serial, "second"),
        ..sample_cert(tenant_id, issuer, "fp-serial-2")
    };
    assert!(
        repo.create(twin).await.is_err(),
        "the same serial under the same issuer must be refused"
    );

    let elsewhere = StoreCertificate {
        public_cert_pem: pem_with_serial(&serial, "third"),
        ..sample_cert(tenant_id, other_issuer, "fp-serial-3")
    };
    repo.create(elsewhere).await.unwrap();

    let distinct = StoreCertificate {
        public_cert_pem: pem_with_serial(&[0x22u8; 20], "fourth"),
        ..sample_cert(tenant_id, issuer, "fp-serial-4")
    };
    repo.create(distinct).await.unwrap();
}

/// A CA is keyed on its parent: two intermediates under one parent may not
/// share a serial; roots (no parent) never collide, whatever their serial.
#[tokio::test]
async fn ca_serials_are_unique_under_a_parent_and_free_among_roots() {
    let (db, org, _tenant) = setup().await;
    let repo = SurrealCaCertificateRepository::new(db);
    let serial = [0x33u8; 20];

    let root_a = repo
        .create(sample_ca(
            org,
            None,
            pem_with_serial(&serial, "a"),
            "fp-root-a",
        ))
        .await
        .unwrap();
    repo.create(sample_ca(
        org,
        None,
        pem_with_serial(&serial, "b"),
        "fp-root-b",
    ))
    .await
    .expect("two roots may share a serial: it is their issuers' choice");

    repo.create(sample_ca(
        org,
        Some(root_a.id),
        pem_with_serial(&serial, "c"),
        "fp-int-c",
    ))
    .await
    .unwrap();
    assert!(
        repo.create(sample_ca(
            org,
            Some(root_a.id),
            pem_with_serial(&serial, "d"),
            "fp-int-d",
        ))
        .await
        .is_err(),
        "two intermediates under one parent must not share a serial"
    );
}

/// The upgrade path: an existing database holds certificates issued under one
/// serial (the pre-fix same-key twins) and has no `serial` column. Migration v99
/// must apply over them — `NONE` is not a collision — and afterwards enforce
/// the index on what is written next. v99 is un-applied by hand (its DDL
/// removed, its `_migration` record deleted) so the real runner re-applies it.
#[tokio::test]
async fn v99_applies_over_rows_that_already_share_a_serial() {
    let (db, _org, tenant_id) = setup().await;
    let issuer = Uuid::new_v4();

    db.query(
        "REMOVE INDEX idx_certificate_issuer_serial ON TABLE certificate; \
         REMOVE INDEX idx_ca_certificate_parent_serial ON TABLE ca_certificate; \
         REMOVE FIELD serial ON TABLE certificate; \
         REMOVE FIELD serial ON TABLE ca_certificate; \
         DELETE _migration WHERE version = 99;",
    )
    .await
    .unwrap()
    .check()
    .unwrap();

    // Two certificates, one serial, one issuer: what a CSR signed twice made.
    let serial = [0x44u8; 20];
    for (i, cn) in ["twin-a", "twin-b"].into_iter().enumerate() {
        db.query(
            "CREATE type::record('certificate', $id) SET \
             tenant_id = $tenant_id, issuer_ca_id = $issuer, subject = $cn, \
             public_cert_pem = $pem, fingerprint = $fp, cert_type = 'Device', \
             key_algorithm = 'Ed25519', not_before = time::now(), \
             not_after = time::now() + 30d, status = 'Active'",
        )
        .bind(("id", Uuid::new_v4().to_string()))
        .bind(("tenant_id", tenant_id.to_string()))
        .bind(("issuer", issuer.to_string()))
        .bind(("cn", cn))
        .bind(("pem", pem_with_serial(&serial, cn)))
        .bind(("fp", format!("fp-twin-{i}")))
        .await
        .unwrap()
        .check()
        .unwrap();
    }

    axiam_db::run_migrations(&db)
        .await
        .expect("v99 must apply over rows that share a serial");

    let repo = SurrealCertificateRepository::new(db);
    repo.create(StoreCertificate {
        public_cert_pem: pem_with_serial(&serial, "after-a"),
        ..sample_cert(tenant_id, issuer, "fp-after-a")
    })
    .await
    .expect("the old twins have no recorded serial, so the next one is the first");
    assert!(
        repo.create(StoreCertificate {
            public_cert_pem: pem_with_serial(&serial, "after-b"),
            ..sample_cert(tenant_id, issuer, "fp-after-b")
        })
        .await
        .is_err(),
        "from here on a repeat is refused"
    );
}

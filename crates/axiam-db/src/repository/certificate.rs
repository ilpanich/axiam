//! SurrealDB implementation of [`CertificateRepository`].

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::id::new_id;
use axiam_core::models::certificate::{
    Certificate, CertificateStatus, CertificateType, KeyAlgorithm, RevocationStamp,
    RevokedCertificate, StoreCertificate, VaultForwardCandidate,
};
use axiam_core::repository::{CertificateRepository, PaginatedResult, Pagination};
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{
    CountRow, classify_write_error, paginate, retry_hot_row, retry_on_write_conflict, search_bind,
    search_filter, take_first_or_not_found,
};
use crate::repository::tenant_purge::PAST_REVOCATION_GRACE;

// ---------------------------------------------------------------------------
// Row structs
// ---------------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct CertificateRow {
    tenant_id: String,
    issuer_ca_id: String,
    subject: String,
    public_cert_pem: String,
    fingerprint: String,
    cert_type: String,
    key_algorithm: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    status: String,
    metadata: serde_json::Value,
    /// #533 (schema v98); NONE on every row issued before it.
    user_id: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct CertificateRowWithId {
    record_id: String,
    tenant_id: String,
    issuer_ca_id: String,
    subject: String,
    public_cert_pem: String,
    fingerprint: String,
    cert_type: String,
    key_algorithm: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    status: String,
    metadata: serde_json::Value,
    /// #533 (schema v98); NONE on every row issued before it.
    user_id: Option<String>,
    created_at: DateTime<Utc>,
}

/// A pending Vault forward: the certificate and the sweep's bookkeeping on it.
#[derive(Debug, SurrealValue)]
struct VaultForwardRow {
    record_id: String,
    tenant_id: String,
    issuer_ca_id: String,
    subject: String,
    public_cert_pem: String,
    fingerprint: String,
    cert_type: String,
    key_algorithm: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    status: String,
    metadata: serde_json::Value,
    user_id: Option<String>,
    created_at: DateTime<Utc>,
    vault_forward_attempts: Option<i64>,
    vault_forward_last_error: Option<String>,
    vault_next_attempt_at: Option<DateTime<Utc>>,
}

impl VaultForwardRow {
    fn try_into_candidate(self) -> Result<VaultForwardCandidate, DbError> {
        let attempts = self.vault_forward_attempts;
        let last_error = self.vault_forward_last_error;
        let next_attempt_at = self.vault_next_attempt_at;
        let certificate = CertificateRowWithId {
            record_id: self.record_id,
            tenant_id: self.tenant_id,
            issuer_ca_id: self.issuer_ca_id,
            subject: self.subject,
            public_cert_pem: self.public_cert_pem,
            fingerprint: self.fingerprint,
            cert_type: self.cert_type,
            key_algorithm: self.key_algorithm,
            not_before: self.not_before,
            not_after: self.not_after,
            status: self.status,
            metadata: self.metadata,
            user_id: self.user_id,
            created_at: self.created_at,
        }
        .try_into_entry()?;
        Ok(VaultForwardCandidate {
            certificate,
            // Rows from before v95 carry no count: none attempted, due now (D-6).
            attempts: attempts.map_or(0, |n| u32::try_from(n.max(0)).unwrap_or(u32::MAX)),
            next_attempt_at,
            last_error,
        })
    }
}

/// The longest error text a row keeps (#603): a status and a short message.
/// The sweep sanitises before it writes; this bound holds whatever the caller
/// sent.
const MAX_FORWARD_ERROR_CHARS: usize = 256;

/// The unforwarded revocations of active `vault_pki` CAs: the rows the sweep
/// is about. One definition for the list, the due list and the count.
const UNFORWARDED_WHERE: &str = "status = 'Revoked' \
       AND vault_revoked_at = NONE \
       AND not_after > time::now() \
       AND issuer_ca_id IN (SELECT VALUE meta::id(id) FROM ca_certificate \
                            WHERE key_custody = 'vault_pki' \
                              AND status = 'Active')";

/// `$taken` and `$unambiguous` for [`BELONGS_TO_ACCOUNT`]: the collision rule of
/// `SurrealUserRepository::identity_collision` — both columns, folded, every
/// status, the account itself left out — computed in the same query as the
/// write that uses it, so no caller can skip it (R101W1-01). Binds `$tenant_id`,
/// `$user_id`, `$names`.
const ACCOUNT_NAMES_PREFIX: &str = "LET $taken = array::flatten( \
         SELECT VALUE [string::lowercase(username), string::lowercase(email)] \
         FROM user \
         WHERE tenant_id = $tenant_id \
           AND meta::id(id) != $user_id \
           AND (string::lowercase(username) IN $names \
                OR string::lowercase(email) IN $names)); \
     LET $unambiguous = array::complement($names, $taken);";

/// The condition under which a `User` certificate belongs to the account being
/// revoked or erased (#533, R101W1-01): the binding, and for a row without one
/// the convention — `metadata.user_id`, or a common name equal to an
/// unambiguous name of the account on a row created since the account was.
/// One definition for the revocation and the metadata scrub, so the second can
/// never reach a row the first would not. Binds `$user_id`, `$user_created_at`.
const BELONGS_TO_ACCOUNT: &str = "(user_id = $user_id \
         OR (user_id = NONE \
             AND (metadata.user_id = $user_id \
                  OR (created_at >= $user_created_at \
                      AND string::lowercase(subject) IN $unambiguous))))";

/// An account's username and email, trimmed and folded, without the empty ones.
fn folded_names(username: &str, email: &str) -> Vec<String> {
    [username, email]
        .into_iter()
        .map(|name| name.trim().to_lowercase())
        .filter(|name| !name.is_empty())
        .collect()
}

#[derive(Debug, SurrealValue)]
struct RevokedCertificateRow {
    #[allow(dead_code)]
    record_id: String,
}

/// One entry of an issuing CA's revocation list (#565).
#[derive(Debug, SurrealValue)]
struct RevokedEntryRow {
    public_cert_pem: String,
    fingerprint: String,
    revoked_at: Option<DateTime<Utc>>,
    not_before: DateTime<Utc>,
}

impl From<RevokedEntryRow> for RevokedCertificate {
    fn from(row: RevokedEntryRow) -> Self {
        Self {
            public_cert_pem: row.public_cert_pem,
            fingerprint: row.fingerprint,
            revoked_at: row.revoked_at,
            not_before: row.not_before,
        }
    }
}

/// What decides whether a revocation list changed (#607): no PEM.
#[derive(Debug, SurrealValue)]
pub(crate) struct RevocationStampRow {
    pub(crate) fingerprint: String,
    pub(crate) revoked_at: Option<DateTime<Utc>>,
    pub(crate) not_before: DateTime<Utc>,
}

impl From<RevocationStampRow> for RevocationStamp {
    fn from(row: RevocationStampRow) -> Self {
        Self {
            fingerprint: row.fingerprint,
            revoked_at: row.revoked_at,
            not_before: row.not_before,
        }
    }
}

#[derive(Debug, SurrealValue)]
struct BoundTargetRow {
    sa_id: String,
}

// ---------------------------------------------------------------------------
// Enum helpers
// ---------------------------------------------------------------------------

fn parse_status(s: &str) -> Result<CertificateStatus, DbError> {
    match s {
        "Active" => Ok(CertificateStatus::Active),
        "Revoked" => Ok(CertificateStatus::Revoked),
        "Expired" => Ok(CertificateStatus::Expired),
        other => Err(DbError::Migration(format!(
            "unknown certificate status: {other}"
        ))),
    }
}

fn status_str(s: &CertificateStatus) -> &'static str {
    match s {
        CertificateStatus::Active => "Active",
        CertificateStatus::Revoked => "Revoked",
        CertificateStatus::Expired => "Expired",
    }
}

fn parse_key_algorithm(s: &str) -> Result<KeyAlgorithm, DbError> {
    match s {
        "Rsa4096" => Ok(KeyAlgorithm::Rsa4096),
        "Ed25519" => Ok(KeyAlgorithm::Ed25519),
        other => Err(DbError::Migration(format!(
            "unknown key algorithm: {other}"
        ))),
    }
}

fn key_algorithm_str(k: &KeyAlgorithm) -> &'static str {
    match k {
        KeyAlgorithm::Rsa4096 => "Rsa4096",
        KeyAlgorithm::Ed25519 => "Ed25519",
    }
}

fn parse_cert_type(s: &str) -> Result<CertificateType, DbError> {
    match s {
        "User" => Ok(CertificateType::User),
        "Service" => Ok(CertificateType::Service),
        "Device" => Ok(CertificateType::Device),
        "Server" => Ok(CertificateType::Server),
        // Reads what a bypass of the service layer might have left behind, so a
        // door refuses it *by type* (and says so) rather than failing opaquely
        // on the read. Nothing writes it: see `cert_type_str`.
        "SamlSigning" => Ok(CertificateType::SamlSigning),
        other => Err(DbError::Migration(format!(
            "unknown certificate type: {other}"
        ))),
    }
}

fn cert_type_str(t: &CertificateType) -> &'static str {
    match t {
        CertificateType::User => "User",
        CertificateType::Service => "Service",
        CertificateType::Device => "Device",
        CertificateType::Server => "Server",
        // Never stored (D-21): the SAML signing leaf lives in
        // `saml_idp_credential`. The arm exists so the match is exhaustive, and
        // the schema's `cert_type` assertion refuses the value if anything ever
        // tries to write it.
        CertificateType::SamlSigning => "SamlSigning",
    }
}

/// The stored user binding (#533): NONE for a row without one.
fn parse_user_id(s: Option<&str>) -> Result<Option<Uuid>, DbError> {
    s.map(|s| Uuid::parse_str(s).map_err(|e| DbError::Migration(format!("invalid user UUID: {e}"))))
        .transpose()
}

// ---------------------------------------------------------------------------
// Row → domain conversion
// ---------------------------------------------------------------------------

impl CertificateRow {
    fn into_entry(self, id: Uuid) -> Result<Certificate, DbError> {
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let issuer_ca_id = Uuid::parse_str(&self.issuer_ca_id)
            .map_err(|e| DbError::Migration(format!("invalid issuer CA UUID: {e}")))?;
        Ok(Certificate {
            id,
            tenant_id,
            issuer_ca_id,
            subject: self.subject,
            public_cert_pem: self.public_cert_pem,
            fingerprint: self.fingerprint,
            cert_type: parse_cert_type(&self.cert_type)?,
            key_algorithm: parse_key_algorithm(&self.key_algorithm)?,
            not_before: self.not_before,
            not_after: self.not_after,
            status: parse_status(&self.status)?,
            metadata: self.metadata,
            user_id: parse_user_id(self.user_id.as_deref())?,
            created_at: self.created_at,
        })
    }
}

impl CertificateRowWithId {
    fn try_into_entry(self) -> Result<Certificate, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let issuer_ca_id = Uuid::parse_str(&self.issuer_ca_id)
            .map_err(|e| DbError::Migration(format!("invalid issuer CA UUID: {e}")))?;
        Ok(Certificate {
            id,
            tenant_id,
            issuer_ca_id,
            subject: self.subject,
            public_cert_pem: self.public_cert_pem,
            fingerprint: self.fingerprint,
            cert_type: parse_cert_type(&self.cert_type)?,
            key_algorithm: parse_key_algorithm(&self.key_algorithm)?,
            not_before: self.not_before,
            not_after: self.not_after,
            status: parse_status(&self.status)?,
            metadata: self.metadata,
            user_id: parse_user_id(self.user_id.as_deref())?,
            created_at: self.created_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct SurrealCertificateRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> SurrealCertificateRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        let db = db.into();
        Self { db }
    }
}

impl<C: Connection> CertificateRepository for SurrealCertificateRepository<C> {
    async fn create(&self, input: StoreCertificate) -> AxiamResult<Certificate> {
        let id = new_id();
        let id_str = id.to_string();

        let result = self
            .db
            .current()
            .query(
                "CREATE type::record('certificate', $id) SET \
                 tenant_id = $tenant_id, \
                 issuer_ca_id = $issuer_ca_id, \
                 subject = $subject, \
                 public_cert_pem = $public_cert_pem, \
                 fingerprint = $fingerprint, \
                 cert_type = $cert_type, \
                 key_algorithm = $key_algorithm, \
                 not_before = $not_before, \
                 not_after = $not_after, \
                 status = $status, \
                 metadata = $metadata, \
                 user_id = $user_id, \
                 serial = $serial",
            )
            .bind(("id", id_str))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("issuer_ca_id", input.issuer_ca_id.to_string()))
            .bind(("subject", input.subject))
            // #653: the serial the certificate carries, recorded so the unique
            // index on `(issuer_ca_id, serial)` refuses a repeat under one
            // issuer. `None` for text that is not a parseable certificate.
            .bind((
                "serial",
                axiam_pki::certificate_serial_hex(&input.public_cert_pem),
            ))
            .bind(("public_cert_pem", input.public_cert_pem))
            .bind(("fingerprint", input.fingerprint))
            .bind(("cert_type", cert_type_str(&input.cert_type)))
            .bind(("key_algorithm", key_algorithm_str(&input.key_algorithm)))
            .bind(("not_before", input.not_before))
            .bind(("not_after", input.not_after))
            .bind(("status", status_str(&CertificateStatus::Active)))
            .bind(("metadata", input.metadata))
            .bind(("user_id", input.user_id.map(|id| id.to_string())))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| classify_write_error(e, "certificate"))?;
        let row: Option<CertificateRow> = result.take(0).map_err(DbError::from)?;
        let row = row.ok_or_else(|| DbError::NotFound {
            entity: "certificate".into(),
            id: id.to_string(),
        })?;

        // Create the signed_by edge (RELATE doesn't accept type::record()).
        let relate_sql = format!(
            "RELATE certificate:`{}`->signed_by->ca_certificate:`{}`",
            id, input.issuer_ca_id,
        );
        self.db
            .current()
            .query(&relate_sql)
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        Ok(row.into_entry(id)?)
    }

    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<Certificate> {
        let result = self
            .db
            .current()
            .query(
                "SELECT * FROM type::record('certificate', $id) \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let row: Option<CertificateRow> = result.take(0).map_err(DbError::from)?;
        let row = row.ok_or_else(|| DbError::NotFound {
            entity: "certificate".into(),
            id: id.to_string(),
        })?;

        Ok(row.into_entry(id)?)
    }

    async fn get_by_fingerprint(
        &self,
        tenant_id: Uuid,
        fingerprint: &str,
    ) -> AxiamResult<Certificate> {
        let result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM certificate \
                 WHERE tenant_id = $tenant_id AND fingerprint = $fingerprint",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("fingerprint", fingerprint.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<CertificateRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "certificate", fingerprint)?;

        row.try_into_entry().map_err(Into::into)
    }

    async fn revoke(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        let result = self
            .db
            .current()
            .query(
                // #565: the first revocation's date stands — a CRL entry says
                // when the CA processed the revocation, and a second revoke of
                // the same certificate is not a second revocation.
                "UPDATE type::record('certificate', $id) SET \
                 status = $status, \
                 revoked_at = revoked_at ?? time::now() \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("status", status_str(&CertificateStatus::Revoked)))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let row: Option<CertificateRow> = result.take(0).map_err(DbError::from)?;
        if row.is_none() {
            return Err(DbError::NotFound {
                entity: "certificate".into(),
                id: id.to_string(),
            }
            .into());
        }

        Ok(())
    }

    async fn list_revoked_by_issuer(
        &self,
        issuer_ca_id: Uuid,
        expiring_after: DateTime<Utc>,
    ) -> AxiamResult<Vec<RevokedCertificate>> {
        let result = self
            .db
            .current()
            .query(
                "SELECT public_cert_pem, fingerprint, revoked_at, not_before FROM certificate \
                 WHERE issuer_ca_id = $issuer_ca_id \
                   AND status = 'Revoked' \
                   AND not_after > $expiring_after \
                 ORDER BY fingerprint",
            )
            .bind(("issuer_ca_id", issuer_ca_id.to_string()))
            .bind(("expiring_after", expiring_after))
            .await
            .map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<RevokedEntryRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn list_revocation_stamps_by_issuer(
        &self,
        issuer_ca_id: Uuid,
        expiring_after: DateTime<Utc>,
    ) -> AxiamResult<Vec<RevocationStamp>> {
        // The same rows as `list_revoked_by_issuer`, without the PEMs (#607).
        let result = self
            .db
            .current()
            .query(
                "SELECT fingerprint, revoked_at, not_before FROM certificate \
                 WHERE issuer_ca_id = $issuer_ca_id \
                   AND status = 'Revoked' \
                   AND not_after > $expiring_after \
                 ORDER BY fingerprint",
            )
            .bind(("issuer_ca_id", issuer_ca_id.to_string()))
            .bind(("expiring_after", expiring_after))
            .await
            .map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<RevocationStampRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn list_unforwarded_revocations(&self, limit: u32) -> AxiamResult<Vec<Certificate>> {
        // A row never attempted has no `vault_next_attempt_at`, which sorts
        // first; then the soonest due, then the oldest revocation.
        let query = format!(
            "SELECT meta::id(id) AS record_id, * FROM certificate \
             WHERE {UNFORWARDED_WHERE} \
             ORDER BY vault_next_attempt_at, revoked_at \
             LIMIT $limit"
        );
        let result = self
            .db
            .current()
            .query(query)
            .bind(("limit", limit))
            .await
            .map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<CertificateRowWithId> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(|row| row.try_into_entry().map_err(Into::into))
            .collect()
    }

    async fn list_due_vault_forwards(
        &self,
        now: DateTime<Utc>,
        limit: u32,
    ) -> AxiamResult<Vec<VaultForwardCandidate>> {
        let query = format!(
            "SELECT meta::id(id) AS record_id, * FROM certificate \
             WHERE {UNFORWARDED_WHERE} \
               AND (vault_next_attempt_at = NONE OR vault_next_attempt_at <= $now) \
             ORDER BY vault_next_attempt_at, revoked_at \
             LIMIT $limit"
        );
        let result = self
            .db
            .current()
            .query(query)
            .bind(("now", now))
            .bind(("limit", limit))
            .await
            .map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<VaultForwardRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(|row| row.try_into_candidate().map_err(Into::into))
            .collect()
    }

    async fn claim_vault_forward(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        seen_next_attempt_at: Option<DateTime<Utc>>,
        lease_until: DateTime<Utc>,
    ) -> AxiamResult<bool> {
        // The value read is the precondition of the write (the SCIM
        // `claim_reconciliation` pattern): of two replicas that read the same
        // row, one write matches and moves the date; the other either matches
        // nothing or loses the optimistic write, retries, and then finds the
        // winner's date. A forwarded row, or another tenant's, matches nothing.
        let seen = if seen_next_attempt_at.is_some() {
            "vault_next_attempt_at = $seen"
        } else {
            "vault_next_attempt_at = NONE"
        };
        let query = format!(
            "UPDATE type::record('certificate', $id) SET vault_next_attempt_at = $lease \
             WHERE tenant_id = $tenant_id \
               AND status = 'Revoked' \
               AND vault_revoked_at = NONE \
               AND {seen} \
             RETURN VALUE meta::id(id)"
        );
        retry_hot_row(|| async {
            let mut result = self
                .db
                .current()
                .query(query.clone())
                .bind(("id", id.to_string()))
                .bind(("tenant_id", tenant_id.to_string()))
                .bind(("seen", seen_next_attempt_at))
                .bind(("lease", lease_until))
                .await
                .map_err(DbError::from)?
                .check()
                .map_err(|e| classify_write_error(e, "certificate"))?;
            let claimed: Vec<String> = result.take(0).map_err(DbError::from)?;
            Ok::<_, DbError>(!claimed.is_empty())
        })
        .await
        .map_err(Into::into)
    }

    async fn record_vault_forward_failure(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        claimed_until: DateTime<Utc>,
        attempts: u32,
        next_attempt_at: DateTime<Utc>,
        error: &str,
    ) -> AxiamResult<bool> {
        // R101W1-09 (d): conditional on the lease the caller's claim wrote, as
        // the claim is on the value it read. A replica whose attempt outlived
        // its lease finds another replica's lease (or a forwarded row) and
        // writes nothing; a write conflict with that replica's claim is
        // retried and then finds the new lease.
        let error: String = error.chars().take(MAX_FORWARD_ERROR_CHARS).collect();
        retry_hot_row(|| async {
            let mut result = self
                .db
                .current()
                .query(
                    "UPDATE type::record('certificate', $id) SET \
                       vault_forward_attempts = $attempts, \
                       vault_forward_last_error = $error, \
                       vault_next_attempt_at = $next \
                     WHERE tenant_id = $tenant_id \
                       AND vault_revoked_at = NONE \
                       AND vault_next_attempt_at = $lease \
                     RETURN VALUE meta::id(id)",
                )
                .bind(("id", id.to_string()))
                .bind(("tenant_id", tenant_id.to_string()))
                .bind(("lease", claimed_until))
                .bind(("attempts", i64::from(attempts)))
                .bind(("error", error.clone()))
                .bind(("next", next_attempt_at))
                .await
                .map_err(DbError::from)?
                .check()
                .map_err(|e| classify_write_error(e, "certificate"))?;
            let written: Vec<String> = result.take(0).map_err(DbError::from)?;
            Ok::<_, DbError>(!written.is_empty())
        })
        .await
        .map_err(Into::into)
    }

    async fn count_vault_forwards_failing(&self, min_attempts: u32) -> AxiamResult<u64> {
        let query = format!(
            "SELECT count() AS total FROM certificate \
             WHERE {UNFORWARDED_WHERE} AND vault_forward_attempts >= $min \
             GROUP ALL"
        );
        let result = self
            .db
            .current()
            .query(query)
            .bind(("min", i64::from(min_attempts)))
            .await
            .map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let row: Option<CountRow> = result.take(0).map_err(DbError::from)?;
        Ok(row.map_or(0, |r| r.total))
    }

    async fn revoke_all_for_tenant(&self, tenant_id: Uuid) -> AxiamResult<Vec<Certificate>> {
        // An expired certificate is on no list and is left as it is; a revoked
        // one keeps its first revocation date (#565).
        let result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM \
                 (UPDATE certificate SET status = 'Revoked', \
                  revoked_at = revoked_at ?? time::now() \
                  WHERE tenant_id = $tenant_id \
                    AND status != 'Revoked' \
                    AND not_after > time::now())",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<CertificateRowWithId> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(|row| row.try_into_entry().map_err(Into::into))
            .collect()
    }

    async fn mark_revocation_forwarded(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        let result = self
            .db
            .current()
            .query(
                // The first forwarding's time stands, as the revocation's does.
                "UPDATE type::record('certificate', $id) SET \
                 vault_revoked_at = vault_revoked_at ?? time::now() \
                 WHERE tenant_id = $tenant_id AND status = 'Revoked'",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let row: Option<CertificateRow> = result.take(0).map_err(DbError::from)?;
        if row.is_none() {
            return Err(DbError::NotFound {
                entity: "certificate".into(),
                id: id.to_string(),
            }
            .into());
        }
        Ok(())
    }

    async fn revoke_user_certificates(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        username: &str,
        email: &str,
        user_created_at: DateTime<Utc>,
    ) -> AxiamResult<u64> {
        // See the trait: the binding first (#533), and the convention —
        // `metadata.user_id`, or the subject common name equalling the
        // account's username or email, ignoring case — only for a row with no
        // binding, so another account's certificate is never matched by name.
        // Only `User`-type certificates that are still active.
        //
        // R101W1-01: the name match is further limited to rows created at or
        // after the account, and to names no other account of the tenant
        // holds. `$taken` is the collision rule of
        // `SurrealUserRepository::identity_collision` — both columns, folded,
        // every status, the account itself left out — computed in the same
        // query as the revocation, so no caller can skip it. The binding and
        // the `metadata.user_id` match (a random id nobody can be named
        // after) are not bounded.
        let names = folded_names(username, email);
        let result = self
            .db
            .current()
            .query(format!(
                "{ACCOUNT_NAMES_PREFIX} \
                 SELECT meta::id(id) AS record_id FROM \
                 (UPDATE certificate SET status = 'Revoked', revoked_at = time::now() \
                  WHERE tenant_id = $tenant_id \
                    AND cert_type = 'User' \
                    AND status = 'Active' \
                    AND {BELONGS_TO_ACCOUNT})"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .bind(("names", names))
            .bind(("user_created_at", user_created_at))
            .await
            .map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        // LET, LET, SELECT.
        let rows: Vec<RevokedCertificateRow> = result.take(2).map_err(DbError::from)?;
        Ok(rows.len() as u64)
    }

    async fn clear_user_certificates_metadata(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        username: &str,
        email: &str,
        user_created_at: DateTime<Utc>,
    ) -> AxiamResult<u64> {
        // The rows `revoke_user_certificates` matches, in any status; the
        // free-form `metadata` is the one column of a kept row that carries
        // what the issuer's operator typed about the holder, and the list does
        // not need it (the tenant purge clears it the same way). `user_id`,
        // the PEM and `subject` stay: see the trait.
        let names = folded_names(username, email);
        let result = self
            .db
            .current()
            .query(format!(
                "{ACCOUNT_NAMES_PREFIX} \
                 SELECT meta::id(id) AS record_id FROM \
                 (UPDATE certificate SET metadata = {{}} \
                  WHERE tenant_id = $tenant_id \
                    AND cert_type = 'User' \
                    AND metadata != {{}} \
                    AND {BELONGS_TO_ACCOUNT})"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .bind(("names", names))
            .bind(("user_created_at", user_created_at))
            .await
            .map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        // LET, LET, SELECT.
        let rows: Vec<RevokedCertificateRow> = result.take(2).map_err(DbError::from)?;
        Ok(rows.len() as u64)
    }

    async fn delete_past_retention(&self, limit: u32) -> AxiamResult<u64> {
        // The batch is chosen first and deleted by id, so `LIMIT` bounds the
        // write; the edge goes before the row it hangs from. Counted from what
        // `DELETE … RETURN BEFORE` returns, i.e. what this call removed: a
        // replica that lost the race for a row deletes nothing and counts
        // nothing. Live tenants only (a tenant row without `deleted_at`).
        //
        // The live tenants are read once into `$live`: written inline as
        // `tenant_id IN (SELECT …)` the subquery is evaluated again for every
        // candidate row (36 s for 3 000 rows and 301 tenants, R110W1-01).
        //
        // Two replicas choosing overlapping batches conflict on the rows they
        // both delete, and the datastore aborts one transaction having
        // committed nothing; replaying it re-chooses its batch from what is
        // left, so a conflict is retried here rather than failing the sweep.
        let removed = retry_on_write_conflict(|| async {
            let mut result = self
                .db
                .current()
                .query(format!(
                    "LET $live = (SELECT VALUE meta::id(id) FROM tenant \
                                  WHERE deleted_at = NONE); \
                     LET $doomed = (SELECT VALUE id FROM certificate \
                         WHERE {PAST_REVOCATION_GRACE} \
                           AND tenant_id IN $live \
                         LIMIT $limit); \
                     DELETE cert_bound_to WHERE in IN $doomed; \
                     LET $removed = (DELETE $doomed RETURN BEFORE); \
                     SELECT meta::id(id) AS record_id FROM $removed"
                ))
                .bind(("limit", limit))
                .await
                .map_err(DbError::from)?
                .check()
                .map_err(|e| DbError::Migration(e.to_string()))?;
            // LET, LET, DELETE, LET, SELECT.
            let rows: Vec<RevokedCertificateRow> = result.take(4).map_err(DbError::from)?;
            Ok::<_, DbError>(rows.len() as u64)
        })
        .await?;
        Ok(removed)
    }

    async fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<Certificate>> {
        let tenant_id_str = tenant_id.to_string();

        // Free-text filter, applied to BOTH queries below so the
        // total counts matches rather than rows — a pager whose page
        // count belongs to a different result set than the page it
        // shows is worse than no pager. Empty when unsearched, so an
        // unfiltered list runs exactly the query it always ran.
        let search = search_filter(&pagination, &["subject", "fingerprint"]);
        let search_term = search_bind(&pagination);

        let count_sql = format!(
            "SELECT count() AS total FROM certificate \
                         WHERE tenant_id = $tenant_id{search} GROUP ALL"
        );
        let count_result = self
            .db
            .current()
            .query(count_sql)
            .bind(("tenant_id", tenant_id_str.clone()))
            .bind(("search", search_term.clone()))
            .await
            .map_err(DbError::from)?;
        let mut count_result = count_result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;

        let data_sql = format!(
            "SELECT meta::id(id) AS record_id, * FROM certificate \
                        WHERE tenant_id = $tenant_id{search} \
                        ORDER BY created_at DESC \
                        LIMIT $limit START $offset"
        );
        let data_result = self
            .db
            .current()
            .query(data_sql)
            .bind(("tenant_id", tenant_id_str))
            .bind(("search", search_term))
            .bind(("limit", pagination.limit))
            .bind(("offset", pagination.offset))
            .await
            .map_err(DbError::from)?;
        let mut data_result = data_result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<CertificateRowWithId> = data_result.take(0).map_err(DbError::from)?;

        let items: Vec<Certificate> = rows
            .into_iter()
            .map(|r| r.try_into_entry())
            .collect::<Result<_, _>>()?;

        Ok(paginate(items, count_rows, &pagination))
    }

    async fn get_by_fingerprint_global(&self, fingerprint: &str) -> AxiamResult<Certificate> {
        let result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM certificate \
                 WHERE fingerprint = $fingerprint",
            )
            .bind(("fingerprint", fingerprint.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<CertificateRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "certificate", fingerprint)?;

        row.try_into_entry().map_err(Into::into)
    }

    async fn bind_to_service_account(
        &self,
        tenant_id: Uuid,
        cert_id: Uuid,
        sa_id: Uuid,
    ) -> AxiamResult<()> {
        // Verify both certificate and service account belong to the same tenant
        // before creating the binding.
        let verify_sql = format!(
            "LET $cert = (SELECT tenant_id FROM certificate:`{cert_id}` WHERE tenant_id = $tid);\
             LET $sa = (SELECT tenant_id FROM service_account:`{sa_id}` WHERE tenant_id = $tid);\
             IF array::len($cert) = 0 OR array::len($sa) = 0 {{ \
                 THROW 'cross-tenant binding denied'; \
             }};\
             RELATE certificate:`{cert_id}`->cert_bound_to->service_account:`{sa_id}`",
        );
        let result = self
            .db
            .current()
            .query(&verify_sql)
            .bind(("tid", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        if let Err(e) = result.check() {
            let msg = e.to_string();
            if msg.contains("cross-tenant binding denied") {
                return Err(AxiamError::AuthorizationDenied {
                    reason: "cross-tenant certificate-to-service-account binding denied".into(),
                    action: None,
                    resource_id: None,
                });
            }
            return Err(classify_write_error(msg, "certificate_binding").into());
        }
        Ok(())
    }

    async fn bound_service_accounts(
        &self,
        cert_ids: &[Uuid],
    ) -> AxiamResult<std::collections::HashMap<Uuid, Uuid>> {
        use std::collections::HashMap;

        if cert_ids.is_empty() {
            return Ok(HashMap::new());
        }

        #[derive(Debug, SurrealValue)]
        struct EdgeRow {
            cert_id: String,
            sa_id: String,
        }

        // One query for the whole page. The `in` side is compared as a record
        // id, so the list is built from the ids rather than bound as strings —
        // they are UUIDs that came from the rows this method's caller just
        // read, so there is nothing here an outside caller can shape.
        let targets = cert_ids
            .iter()
            .map(|id| format!("certificate:`{id}`"))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT meta::id(in) AS cert_id, meta::id(out) AS sa_id \
             FROM cert_bound_to WHERE in IN [{targets}]"
        );

        let result = self.db.current().query(&sql).await.map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<EdgeRow> = result.take(0).map_err(DbError::from)?;

        let mut out = HashMap::with_capacity(rows.len());
        for row in rows {
            let cert = Uuid::parse_str(&row.cert_id)
                .map_err(|e| DbError::Migration(format!("invalid certificate UUID: {e}")))?;
            let sa = Uuid::parse_str(&row.sa_id)
                .map_err(|e| DbError::Migration(format!("invalid service account UUID: {e}")))?;
            out.insert(cert, sa);
        }
        Ok(out)
    }

    async fn get_bound_service_account(&self, cert_id: Uuid) -> AxiamResult<Option<Uuid>> {
        // Use a subquery to extract the service_account ID as a string
        let sql = format!(
            "SELECT meta::id(out) AS sa_id FROM cert_bound_to \
             WHERE in = certificate:`{}`",
            cert_id,
        );
        let result = self.db.current().query(&sql).await.map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<BoundTargetRow> = result.take(0).map_err(DbError::from)?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };

        let sa_id = Uuid::parse_str(&row.sa_id)
            .map_err(|e| DbError::Migration(format!("invalid service account UUID: {e}")))?;
        Ok(Some(sa_id))
    }
}

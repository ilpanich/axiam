//! SurrealDB implementation of [`CaCertificateRepository`].

use axiam_core::ca_keys::CaKeyCustody;
use axiam_core::error::AxiamResult;
use axiam_core::models::certificate::{
    CaCertificate, CaVaultForwardCandidate, CertificateStatus, KeyAlgorithm, RevocationStamp,
    RevokedCertificate, StoreCaCertificate,
};
use axiam_core::repository::{CaCertificateRepository, PaginatedResult, Pagination};
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{CountRow, classify_write_error, paginate, retry_hot_row};

// ---------------------------------------------------------------------------
// Row structs
// ---------------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct CaCertificateRow {
    organization_id: String,
    /// Schema v47. `None` for an organization CA, which is every row written
    /// before the migration.
    tenant_id: Option<String>,
    /// Schema v47. `None` for a CA with no parent inside AXIAM.
    parent_ca_id: Option<String>,
    subject: String,
    public_cert_pem: String,
    /// Schema v46. `Option` for every row written before it, and for every CA
    /// that is its own root.
    chain_pem: Option<String>,
    fingerprint: String,
    key_algorithm: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    status: String,
    encrypted_private_key: Option<surrealdb_types::Bytes>,
    /// Schema v45. `Option` so a row written before the migration still
    /// deserializes; `decode_custody` resolves it the way the backfill does.
    key_custody: Option<String>,
    key_locator: Option<String>,
    /// Schema v49. `None` for every row written before it, which means `false`:
    /// a CA nobody has flagged is not a trust anchor.
    mtls_trust_anchor: Option<bool>,
    created_at: DateTime<Utc>,
}

/// One subordinate CA on its parent's revocation list (#565).
#[derive(Debug, SurrealValue)]
struct RevokedCaRow {
    public_cert_pem: String,
    fingerprint: String,
    /// Schema v90. `None` for a CA revoked before it.
    revoked_at: Option<DateTime<Utc>>,
    not_before: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct CaCertificateRowWithId {
    record_id: String,
    organization_id: String,
    /// Schema v47. `None` for an organization CA, which is every row written
    /// before the migration.
    tenant_id: Option<String>,
    /// Schema v47. `None` for a CA with no parent inside AXIAM.
    parent_ca_id: Option<String>,
    subject: String,
    public_cert_pem: String,
    /// Schema v46. `Option` for every row written before it, and for every CA
    /// that is its own root.
    chain_pem: Option<String>,
    fingerprint: String,
    key_algorithm: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    status: String,
    encrypted_private_key: Option<surrealdb_types::Bytes>,
    /// Schema v45. `Option` so a row written before the migration still
    /// deserializes; `decode_custody` resolves it the way the backfill does.
    key_custody: Option<String>,
    key_locator: Option<String>,
    /// Schema v49. `None` for every row written before it, which means `false`:
    /// a CA nobody has flagged is not a trust anchor.
    mtls_trust_anchor: Option<bool>,
    created_at: DateTime<Utc>,
}

/// A pending Vault forward of a revoked subordinate CA: the row and the
/// sweep's bookkeeping on it (#612).
#[derive(Debug, SurrealValue)]
struct CaVaultForwardRow {
    record_id: String,
    organization_id: String,
    tenant_id: Option<String>,
    parent_ca_id: Option<String>,
    subject: String,
    public_cert_pem: String,
    chain_pem: Option<String>,
    fingerprint: String,
    key_algorithm: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    status: String,
    encrypted_private_key: Option<surrealdb_types::Bytes>,
    key_custody: Option<String>,
    key_locator: Option<String>,
    mtls_trust_anchor: Option<bool>,
    created_at: DateTime<Utc>,
    vault_forward_attempts: Option<i64>,
    vault_forward_last_error: Option<String>,
    vault_next_attempt_at: Option<DateTime<Utc>>,
}

impl CaVaultForwardRow {
    fn try_into_candidate(self) -> Result<CaVaultForwardCandidate, DbError> {
        let attempts = self.vault_forward_attempts;
        let last_error = self.vault_forward_last_error;
        let next_attempt_at = self.vault_next_attempt_at;
        let ca = CaCertificateRowWithId {
            record_id: self.record_id,
            organization_id: self.organization_id,
            tenant_id: self.tenant_id,
            parent_ca_id: self.parent_ca_id,
            subject: self.subject,
            public_cert_pem: self.public_cert_pem,
            chain_pem: self.chain_pem,
            fingerprint: self.fingerprint,
            key_algorithm: self.key_algorithm,
            not_before: self.not_before,
            not_after: self.not_after,
            status: self.status,
            encrypted_private_key: self.encrypted_private_key,
            key_custody: self.key_custody,
            key_locator: self.key_locator,
            mtls_trust_anchor: self.mtls_trust_anchor,
            created_at: self.created_at,
        }
        .try_into_entry()?;
        Ok(CaVaultForwardCandidate {
            ca,
            // Rows from before v96 carry no count: none attempted, due now (D-6).
            attempts: attempts.map_or(0, |n| u32::try_from(n.max(0)).unwrap_or(u32::MAX)),
            next_attempt_at,
            last_error,
        })
    }
}

/// The longest error text a row keeps (#612), as on the leaf table.
const MAX_FORWARD_ERROR_CHARS: usize = 256;

/// The revoked, unexpired subordinate CAs whose parent's list Vault keeps and
/// has not been told of (#612): the parent is an active `vault_pki` CA, and the
/// row was signed there (`vault_pki`, or `external` — a caller's CSR the parent
/// signed). One definition for the due list and the count.
const UNFORWARDED_WHERE: &str = "status = 'Revoked' \
       AND vault_revoked_at = NONE \
       AND not_after > time::now() \
       AND key_custody IN ['vault_pki', 'external'] \
       AND parent_ca_id IN (SELECT VALUE meta::id(id) FROM ca_certificate \
                            WHERE key_custody = 'vault_pki' \
                              AND status = 'Active')";

// ---------------------------------------------------------------------------
// Enum helpers
// ---------------------------------------------------------------------------

/// Resolve a row's custodian, tolerating one written before schema v45.
///
/// Same rule as the migration's backfill, and here for the same reason it is
/// there: a row holding ciphertext has its key in itself, and one holding none
/// never had a key here at all. Reading the second as `Database` would produce
/// a CA that claims a key it does not have and fails at issuance with a
/// decryption error rather than a sentence.
///
/// An unparseable value falls back the same way rather than failing the read: a
/// cosmetic column must not take CA listing down for the whole organization.
fn decode_custody(stored: Option<&str>, has_ciphertext: bool) -> CaKeyCustody {
    match stored.and_then(|v| v.parse::<CaKeyCustody>().ok()) {
        Some(custody) => custody,
        None if has_ciphertext => CaKeyCustody::Database,
        None => CaKeyCustody::External,
    }
}

/// Read a nullable UUID column.
///
/// A stored value that will not parse is a corrupt row rather than an absent
/// one, and is reported as such: silently reading it as `None` would turn a
/// tenant signing CA into an organization CA, which is a change in who is
/// allowed to see it.
fn parse_optional_uuid(stored: Option<&str>, column: &str) -> Result<Option<Uuid>, DbError> {
    stored
        .filter(|v| !v.is_empty())
        .map(|v| {
            Uuid::parse_str(v)
                .map_err(|e| DbError::Migration(format!("invalid {column} UUID: {e}")))
        })
        .transpose()
}

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

// ---------------------------------------------------------------------------
// Row → domain conversion
// ---------------------------------------------------------------------------

impl CaCertificateRow {
    fn into_entry(self, id: Uuid) -> Result<CaCertificate, DbError> {
        let organization_id = Uuid::parse_str(&self.organization_id)
            .map_err(|e| DbError::Migration(format!("invalid org UUID: {e}")))?;
        Ok(CaCertificate {
            id,
            organization_id,
            tenant_id: parse_optional_uuid(self.tenant_id.as_deref(), "tenant_id")?,
            parent_ca_id: parse_optional_uuid(self.parent_ca_id.as_deref(), "parent_ca_id")?,
            subject: self.subject,
            public_cert_pem: self.public_cert_pem,
            chain_pem: self.chain_pem,
            fingerprint: self.fingerprint,
            key_algorithm: parse_key_algorithm(&self.key_algorithm)?,
            not_before: self.not_before,
            not_after: self.not_after,
            status: parse_status(&self.status)?,
            key_custody: decode_custody(
                self.key_custody.as_deref(),
                self.encrypted_private_key.is_some(),
            ),
            key_locator: self.key_locator,
            mtls_trust_anchor: self.mtls_trust_anchor.unwrap_or(false),
            encrypted_private_key: self.encrypted_private_key.map(|b| b.into_inner().to_vec()),
            created_at: self.created_at,
        })
    }
}

impl CaCertificateRowWithId {
    fn try_into_entry(self) -> Result<CaCertificate, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let organization_id = Uuid::parse_str(&self.organization_id)
            .map_err(|e| DbError::Migration(format!("invalid org UUID: {e}")))?;
        Ok(CaCertificate {
            id,
            organization_id,
            tenant_id: parse_optional_uuid(self.tenant_id.as_deref(), "tenant_id")?,
            parent_ca_id: parse_optional_uuid(self.parent_ca_id.as_deref(), "parent_ca_id")?,
            subject: self.subject,
            public_cert_pem: self.public_cert_pem,
            chain_pem: self.chain_pem,
            fingerprint: self.fingerprint,
            key_algorithm: parse_key_algorithm(&self.key_algorithm)?,
            not_before: self.not_before,
            not_after: self.not_after,
            status: parse_status(&self.status)?,
            key_custody: decode_custody(
                self.key_custody.as_deref(),
                self.encrypted_private_key.is_some(),
            ),
            key_locator: self.key_locator,
            mtls_trust_anchor: self.mtls_trust_anchor.unwrap_or(false),
            encrypted_private_key: self.encrypted_private_key.map(|b| b.into_inner().to_vec()),
            created_at: self.created_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct SurrealCaCertificateRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> SurrealCaCertificateRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        let db = db.into();
        Self { db }
    }
}

impl<C: Connection> CaCertificateRepository for SurrealCaCertificateRepository<C> {
    async fn create(&self, input: StoreCaCertificate) -> AxiamResult<CaCertificate> {
        // The id comes from the caller, not from `new_id()` here: a custodian
        // outside the database addresses the key by CA id, so the id has to
        // exist before the key is stored, and the key has to be stored before
        // the row.
        let id = input.id;
        let id_str = id.to_string();

        let result = self
            .db
            .current()
            .query(
                "CREATE type::record('ca_certificate', $id) SET \
                 organization_id = $org_id, \
                 tenant_id = $tenant_id, \
                 parent_ca_id = $parent_ca_id, \
                 subject = $subject, \
                 public_cert_pem = $public_cert_pem, \
                 chain_pem = $chain_pem, \
                 fingerprint = $fingerprint, \
                 key_algorithm = $key_algorithm, \
                 not_before = $not_before, \
                 not_after = $not_after, \
                 status = $status, \
                 encrypted_private_key = $encrypted_private_key, \
                 key_custody = $key_custody, \
                 key_locator = $key_locator, \
                 serial = $serial, \
                 mtls_trust_anchor = false",
            )
            .bind(("id", id_str))
            // #653: recorded only for a CA with a parent in AXIAM, whose serial
            // that parent chose; the unique index is `(parent_ca_id, serial)`.
            // A root's serial is its (possibly foreign) issuer's choice and is
            // not unique across roots, so it is left unrecorded.
            .bind((
                "serial",
                input
                    .parent_ca_id
                    .and_then(|_| axiam_pki::certificate_serial_hex(&input.public_cert_pem)),
            ))
            .bind(("org_id", input.organization_id.to_string()))
            .bind(("tenant_id", input.tenant_id.map(|t| t.to_string())))
            .bind(("parent_ca_id", input.parent_ca_id.map(|p| p.to_string())))
            .bind(("subject", input.subject))
            .bind(("public_cert_pem", input.public_cert_pem))
            .bind(("chain_pem", input.chain_pem))
            .bind(("fingerprint", input.fingerprint))
            .bind(("key_algorithm", key_algorithm_str(&input.key_algorithm)))
            .bind(("not_before", input.not_before))
            .bind(("not_after", input.not_after))
            .bind(("status", status_str(&CertificateStatus::Active)))
            .bind((
                "encrypted_private_key",
                input
                    .encrypted_private_key
                    .map(surrealdb_types::Bytes::from),
            ))
            .bind(("key_custody", input.key_custody.to_string()))
            .bind(("key_locator", input.key_locator))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let row: Option<CaCertificateRow> = result.take(0).map_err(DbError::from)?;
        let row = row.ok_or_else(|| DbError::NotFound {
            entity: "ca_certificate".into(),
            id: id.to_string(),
        })?;

        Ok(row.into_entry(id)?)
    }

    async fn get_by_id(&self, organization_id: Uuid, id: Uuid) -> AxiamResult<CaCertificate> {
        let result = self
            .db
            .current()
            .query(
                "SELECT * FROM type::record('ca_certificate', $id) \
                 WHERE organization_id = $org_id",
            )
            .bind(("id", id.to_string()))
            .bind(("org_id", organization_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let row: Option<CaCertificateRow> = result.take(0).map_err(DbError::from)?;
        let row = row.ok_or_else(|| DbError::NotFound {
            entity: "ca_certificate".into(),
            id: id.to_string(),
        })?;

        Ok(row.into_entry(id)?)
    }

    async fn revoke(&self, organization_id: Uuid, id: Uuid) -> AxiamResult<()> {
        let result = self
            .db
            .current()
            .query(
                // #565: the first revocation's date stands, as on the leaf
                // table — it is what the parent's revocation list states.
                "UPDATE type::record('ca_certificate', $id) SET \
                 status = $status, \
                 revoked_at = revoked_at ?? time::now() \
                 WHERE organization_id = $org_id",
            )
            .bind(("id", id.to_string()))
            .bind(("org_id", organization_id.to_string()))
            .bind(("status", status_str(&CertificateStatus::Revoked)))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let row: Option<CaCertificateRow> = result.take(0).map_err(DbError::from)?;
        if row.is_none() {
            return Err(DbError::NotFound {
                entity: "ca_certificate".into(),
                id: id.to_string(),
            }
            .into());
        }

        Ok(())
    }

    async fn list_by_organization(
        &self,
        organization_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<CaCertificate>> {
        let org_id_str = organization_id.to_string();

        // Count query.
        let count_sql = "SELECT count() AS total FROM ca_certificate \
                         WHERE organization_id = $org_id GROUP ALL";
        let count_result = self
            .db
            .current()
            .query(count_sql)
            .bind(("org_id", org_id_str.clone()))
            .await
            .map_err(DbError::from)?;
        let mut count_result = count_result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;

        // Data query.
        let data_sql = "SELECT meta::id(id) AS record_id, * FROM ca_certificate \
                        WHERE organization_id = $org_id \
                        ORDER BY created_at DESC \
                        LIMIT $limit START $offset";
        let data_result = self
            .db
            .current()
            .query(data_sql)
            .bind(("org_id", org_id_str))
            .bind(("limit", pagination.limit))
            .bind(("offset", pagination.offset))
            .await
            .map_err(DbError::from)?;
        let mut data_result = data_result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<CaCertificateRowWithId> = data_result.take(0).map_err(DbError::from)?;

        let items: Vec<CaCertificate> = rows
            .into_iter()
            .map(|r| r.try_into_entry())
            .collect::<Result<_, _>>()?;

        Ok(paginate(items, count_rows, &pagination))
    }

    async fn list_by_tenant(
        &self,
        organization_id: Uuid,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<CaCertificate>> {
        let org_id_str = organization_id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let count_sql = "SELECT count() AS total FROM ca_certificate \
                         WHERE organization_id = $org_id AND tenant_id = $tenant_id \
                         GROUP ALL";
        let count_result = self
            .db
            .current()
            .query(count_sql)
            .bind(("org_id", org_id_str.clone()))
            .bind(("tenant_id", tenant_id_str.clone()))
            .await
            .map_err(DbError::from)?;
        let mut count_result = count_result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;

        // Both predicates, not just the tenant: a tenant id is a UUID and
        // therefore unguessable, but unguessable is not an authorisation check,
        // and the organization scope is the one the handler verified.
        let data_sql = "SELECT meta::id(id) AS record_id, * FROM ca_certificate \
                        WHERE organization_id = $org_id AND tenant_id = $tenant_id \
                        ORDER BY created_at DESC \
                        LIMIT $limit START $offset";
        let data_result = self
            .db
            .current()
            .query(data_sql)
            .bind(("org_id", org_id_str))
            .bind(("tenant_id", tenant_id_str))
            .bind(("limit", pagination.limit))
            .bind(("offset", pagination.offset))
            .await
            .map_err(DbError::from)?;
        let mut data_result = data_result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<CaCertificateRowWithId> = data_result.take(0).map_err(DbError::from)?;

        let items: Vec<CaCertificate> = rows
            .into_iter()
            .map(|r| r.try_into_entry())
            .collect::<Result<_, _>>()?;

        Ok(paginate(items, count_rows, &pagination))
    }

    async fn get_by_issuer_id(&self, id: Uuid) -> AxiamResult<CaCertificate> {
        let result = self
            .db
            .current()
            .query("SELECT * FROM type::record('ca_certificate', $id)")
            .bind(("id", id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let row: Option<CaCertificateRow> = result.take(0).map_err(DbError::from)?;
        let row = row.ok_or_else(|| DbError::NotFound {
            entity: "ca_certificate".into(),
            id: id.to_string(),
        })?;

        Ok(row.into_entry(id)?)
    }

    async fn set_mtls_trust_anchor(
        &self,
        organization_id: Uuid,
        id: Uuid,
        enabled: bool,
    ) -> AxiamResult<CaCertificate> {
        // The organization guard is on the UPDATE itself, not a read-then-write:
        // a caller supplying another organization's CA id must match zero rows
        // and get a not-found, not flip a flag on a CA they cannot see.
        let result = self
            .db
            .current()
            .query(
                "UPDATE type::record('ca_certificate', $id) SET \
                 mtls_trust_anchor = $enabled \
                 WHERE organization_id = $org_id",
            )
            .bind(("id", id.to_string()))
            .bind(("org_id", organization_id.to_string()))
            .bind(("enabled", enabled))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<CaCertificateRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "ca_certificate".into(),
            id: id.to_string(),
        })?;

        Ok(row.into_entry(id)?)
    }

    async fn update_key_custody(
        &self,
        organization_id: Uuid,
        id: Uuid,
        custody: CaKeyCustody,
        key_locator: Option<String>,
        encrypted_private_key: Option<Vec<u8>>,
    ) -> AxiamResult<CaCertificate> {
        // Custody, locator and ciphertext move in ONE statement. Two would
        // leave a window in which the row names Vault *and* still holds the
        // ciphertext — a key that is in both places is not a key that has been
        // moved — and, in the other direction, a window in which it names the
        // database and holds nothing.
        let result = self
            .db
            .current()
            .query(
                "UPDATE type::record('ca_certificate', $id) SET \
                 key_custody = $custody, \
                 key_locator = $key_locator, \
                 encrypted_private_key = $encrypted_private_key \
                 WHERE organization_id = $org_id",
            )
            .bind(("id", id.to_string()))
            .bind(("org_id", organization_id.to_string()))
            .bind(("custody", custody.to_string()))
            .bind(("key_locator", key_locator))
            .bind((
                "encrypted_private_key",
                encrypted_private_key.map(surrealdb_types::Bytes::from),
            ))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<CaCertificateRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "ca_certificate".into(),
            id: id.to_string(),
        })?;

        Ok(row.into_entry(id)?)
    }

    async fn list_revoked_children(
        &self,
        parent_ca_id: Uuid,
        expiring_after: DateTime<Utc>,
    ) -> AxiamResult<Vec<RevokedCertificate>> {
        let result = self
            .db
            .current()
            .query(
                "SELECT public_cert_pem, fingerprint, revoked_at, not_before FROM ca_certificate \
                 WHERE parent_ca_id = $parent_ca_id \
                   AND status = 'Revoked' \
                   AND not_after > $expiring_after \
                 ORDER BY fingerprint",
            )
            .bind(("parent_ca_id", parent_ca_id.to_string()))
            .bind(("expiring_after", expiring_after))
            .await
            .map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<RevokedCaRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows
            .into_iter()
            .map(|row| RevokedCertificate {
                public_cert_pem: row.public_cert_pem,
                fingerprint: row.fingerprint,
                revoked_at: row.revoked_at,
                not_before: row.not_before,
            })
            .collect())
    }

    async fn list_revoked_children_stamps(
        &self,
        parent_ca_id: Uuid,
        expiring_after: DateTime<Utc>,
    ) -> AxiamResult<Vec<RevocationStamp>> {
        // The same rows as `list_revoked_children`, without the PEMs (#607).
        let result = self
            .db
            .current()
            .query(
                "SELECT fingerprint, revoked_at, not_before FROM ca_certificate \
                 WHERE parent_ca_id = $parent_ca_id \
                   AND status = 'Revoked' \
                   AND not_after > $expiring_after \
                 ORDER BY fingerprint",
            )
            .bind(("parent_ca_id", parent_ca_id.to_string()))
            .bind(("expiring_after", expiring_after))
            .await
            .map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<super::certificate::RevocationStampRow> =
            result.take(0).map_err(DbError::from)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn list_mtls_trust_anchors(&self) -> AxiamResult<Vec<CaCertificate>> {
        // Not organization-scoped, by design — see the trait's doc comment.
        //
        // `status = 'Active'` and the notAfter guard are the security-relevant
        // half: a revoked CA in the client trust store would let a certificate
        // the operator has already disowned authenticate a client, and an
        // expired one is a root whose own chain no longer validates.
        let result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM ca_certificate \
                 WHERE mtls_trust_anchor = true \
                   AND status = 'Active' \
                   AND not_after > time::now() \
                 ORDER BY created_at ASC",
            )
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<CaCertificateRowWithId> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(|row| row.try_into_entry().map_err(Into::into))
            .collect()
    }

    async fn list_by_fingerprints(
        &self,
        fingerprints: &[String],
    ) -> AxiamResult<Vec<CaCertificate>> {
        // Not organization-scoped, by design — see the trait's doc comment.
        // Every status: the caller decides what a revoked record means.
        if fingerprints.is_empty() {
            return Ok(Vec::new());
        }
        let result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM ca_certificate \
                 WHERE fingerprint IN $fingerprints",
            )
            .bind(("fingerprints", fingerprints.to_vec()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<CaCertificateRowWithId> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(|row| row.try_into_entry().map_err(Into::into))
            .collect()
    }

    async fn list_due_vault_forwards(
        &self,
        now: DateTime<Utc>,
        limit: u32,
    ) -> AxiamResult<Vec<CaVaultForwardCandidate>> {
        // The leaf table's order: a row never attempted first, then the
        // soonest due, then the oldest revocation.
        let query = format!(
            "SELECT meta::id(id) AS record_id, * FROM ca_certificate \
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
        let rows: Vec<CaVaultForwardRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(|row| row.try_into_candidate().map_err(Into::into))
            .collect()
    }

    async fn claim_vault_forward(
        &self,
        organization_id: Uuid,
        id: Uuid,
        seen_next_attempt_at: Option<DateTime<Utc>>,
        lease_until: DateTime<Utc>,
    ) -> AxiamResult<bool> {
        // The leaf table's claim (#603): the value read is the write's
        // precondition, so of two replicas that read one row exactly one write
        // matches. A forwarded row, or another organization's, matches nothing.
        let seen = if seen_next_attempt_at.is_some() {
            "vault_next_attempt_at = $seen"
        } else {
            "vault_next_attempt_at = NONE"
        };
        let query = format!(
            "UPDATE type::record('ca_certificate', $id) SET vault_next_attempt_at = $lease \
             WHERE organization_id = $org_id \
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
                .bind(("org_id", organization_id.to_string()))
                .bind(("seen", seen_next_attempt_at))
                .bind(("lease", lease_until))
                .await
                .map_err(DbError::from)?
                .check()
                .map_err(|e| classify_write_error(e, "ca_certificate"))?;
            let claimed: Vec<String> = result.take(0).map_err(DbError::from)?;
            Ok::<_, DbError>(!claimed.is_empty())
        })
        .await
        .map_err(Into::into)
    }

    async fn record_vault_forward_failure(
        &self,
        organization_id: Uuid,
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
                    "UPDATE type::record('ca_certificate', $id) SET \
                       vault_forward_attempts = $attempts, \
                       vault_forward_last_error = $error, \
                       vault_next_attempt_at = $next \
                     WHERE organization_id = $org_id \
                       AND vault_revoked_at = NONE \
                       AND vault_next_attempt_at = $lease \
                     RETURN VALUE meta::id(id)",
                )
                .bind(("id", id.to_string()))
                .bind(("org_id", organization_id.to_string()))
                .bind(("lease", claimed_until))
                .bind(("attempts", i64::from(attempts)))
                .bind(("error", error.clone()))
                .bind(("next", next_attempt_at))
                .await
                .map_err(DbError::from)?
                .check()
                .map_err(|e| classify_write_error(e, "ca_certificate"))?;
            let written: Vec<String> = result.take(0).map_err(DbError::from)?;
            Ok::<_, DbError>(!written.is_empty())
        })
        .await
        .map_err(Into::into)
    }

    async fn count_vault_forwards_failing(&self, min_attempts: u32) -> AxiamResult<u64> {
        let query = format!(
            "SELECT count() AS total FROM ca_certificate \
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

    async fn mark_revocation_forwarded(&self, organization_id: Uuid, id: Uuid) -> AxiamResult<()> {
        let result = self
            .db
            .current()
            .query(
                // The first forwarding's time stands, as the revocation's does.
                "UPDATE type::record('ca_certificate', $id) SET \
                 vault_revoked_at = vault_revoked_at ?? time::now() \
                 WHERE organization_id = $org_id AND status = 'Revoked' \
                 RETURN VALUE meta::id(id)",
            )
            .bind(("id", id.to_string()))
            .bind(("org_id", organization_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let marked: Vec<String> = result.take(0).map_err(DbError::from)?;
        if marked.is_empty() {
            return Err(DbError::NotFound {
                entity: "ca_certificate".into(),
                id: id.to_string(),
            }
            .into());
        }
        Ok(())
    }
}

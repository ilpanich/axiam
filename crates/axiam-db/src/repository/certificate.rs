//! SurrealDB implementation of [`CertificateRepository`].

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::id::new_id;
use axiam_core::models::certificate::{
    Certificate, CertificateStatus, CertificateType, KeyAlgorithm, RevokedCertificate,
    StoreCertificate,
};
use axiam_core::repository::{CertificateRepository, PaginatedResult, Pagination};
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{
    CountRow, classify_write_error, paginate, search_bind, search_filter, take_first_or_not_found,
};

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
    created_at: DateTime<Utc>,
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
                 metadata = $metadata",
            )
            .bind(("id", id_str))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("issuer_ca_id", input.issuer_ca_id.to_string()))
            .bind(("subject", input.subject))
            .bind(("public_cert_pem", input.public_cert_pem))
            .bind(("fingerprint", input.fingerprint))
            .bind(("cert_type", cert_type_str(&input.cert_type)))
            .bind(("key_algorithm", key_algorithm_str(&input.key_algorithm)))
            .bind(("not_before", input.not_before))
            .bind(("not_after", input.not_after))
            .bind(("status", status_str(&CertificateStatus::Active)))
            .bind(("metadata", input.metadata))
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
    ) -> AxiamResult<Vec<RevokedCertificate>> {
        let result = self
            .db
            .current()
            .query(
                "SELECT public_cert_pem, fingerprint, revoked_at, not_before FROM certificate \
                 WHERE issuer_ca_id = $issuer_ca_id \
                   AND status = 'Revoked' \
                   AND not_after > time::now() \
                 ORDER BY fingerprint",
            )
            .bind(("issuer_ca_id", issuer_ca_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<RevokedEntryRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn list_unforwarded_revocations(&self, limit: u32) -> AxiamResult<Vec<Certificate>> {
        let result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM certificate \
                 WHERE status = 'Revoked' \
                   AND vault_revoked_at = NONE \
                   AND not_after > time::now() \
                   AND issuer_ca_id IN (SELECT VALUE meta::id(id) FROM ca_certificate \
                                        WHERE key_custody = 'vault_pki' \
                                          AND status = 'Active') \
                 ORDER BY revoked_at \
                 LIMIT $limit",
            )
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
    ) -> AxiamResult<u64> {
        // See the trait for why "belongs to" is a convention here. A
        // certificate matches on `metadata.user_id`, or on its subject common
        // name equalling the account's username or email, ignoring case — and
        // only `User`-type certificates that are still active.
        let names: Vec<String> = [username, email]
            .into_iter()
            .map(|name| name.trim().to_lowercase())
            .filter(|name| !name.is_empty())
            .collect();
        let result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id FROM \
                 (UPDATE certificate SET status = 'Revoked', revoked_at = time::now() \
                  WHERE tenant_id = $tenant_id \
                    AND cert_type = 'User' \
                    AND status = 'Active' \
                    AND (metadata.user_id = $user_id \
                         OR string::lowercase(subject) IN $names))",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .bind(("names", names))
            .await
            .map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<RevokedCertificateRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows.len() as u64)
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

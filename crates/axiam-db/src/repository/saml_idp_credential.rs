//! SurrealDB implementation of [`SamlIdpCredentialRepository`] (G-2, D-21,
//! T23.2.1).
//!
//! One row per credential, tenant-scoped, **not** a `certificate` row. Two
//! properties are the datastore's, not this file's:
//!
//! * *At most one `active` and one `next` per tenant.* The `slot` column is a
//!   `VALUE` expression evaluated by the database on every write and
//!   `idx_saml_idp_credential_slot` is UNIQUE over it, so a second occupant is an
//!   index violation whichever caller wrote it. This file only maps that
//!   violation to `AlreadyExists`.
//! * *The key is ciphertext.* The column is `option<bytes>` and the value written
//!   is what `axiam_pki` sealed under `pki_encryption_key`; there is no column a
//!   plaintext key could be written to.
//!
//! Key material is read by exactly one method, [`get_active_sealed`], through a
//! separate projection ([`SEALED_COLUMNS`]); every other read selects
//! [`COLUMNS`], which does not name the key columns, so no list or get can return
//! one by accident. Errors and messages here never format a row.
//!
//! [`get_active_sealed`]: SamlIdpCredentialRepository::get_active_sealed

use axiam_core::ca_keys::CaKeyCustody;
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::saml_idp_credential::{
    SamlIdpCredential, SamlIdpCredentialPromotion, SamlIdpCredentialStatus,
    SealedSamlIdpCredential, SealedSamlIdpKey, StoreSamlIdpCredential,
};
use axiam_core::repository::SamlIdpCredentialRepository;
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{
    DELETE_TARGET_MISSING, classify_write_error, is_write_conflict, parse_uuid,
    retry_on_write_conflict, take_first_or_not_found,
};

const ENTITY: &str = "saml_idp_credential";

/// `THROW` text: the credential is not the tenant's current `next`.
const PROMOTE_NOT_NEXT: &str = "axiam:saml_idp_promote_not_next";
/// `THROW` text: the credential's validity window does not contain now.
const PROMOTE_OUTSIDE_WINDOW: &str = "axiam:saml_idp_promote_outside_window";

/// Every column **except** the key columns.
const COLUMNS: &str = "meta::id(id) AS record_id, tenant_id, issuer_ca_id, certificate_pem, \
    serial, fingerprint, not_before, not_after, status, key_custody, created_at, retired_at";

/// [`COLUMNS`] plus the sealed key. Used by `get_active_sealed` and nothing else.
const SEALED_COLUMNS: &str = "meta::id(id) AS record_id, tenant_id, issuer_ca_id, \
    certificate_pem, serial, fingerprint, not_before, not_after, status, key_custody, \
    created_at, retired_at, key_locator, encrypted_private_key";

#[derive(Debug, SurrealValue)]
struct CredentialRow {
    record_id: String,
    tenant_id: String,
    issuer_ca_id: String,
    certificate_pem: String,
    serial: String,
    fingerprint: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    status: String,
    key_custody: String,
    created_at: DateTime<Utc>,
    retired_at: Option<DateTime<Utc>>,
}

/// A row with the key columns. Its `Debug` is hand-written so a stray `{:?}`
/// cannot print the ciphertext.
#[derive(SurrealValue)]
struct SealedRow {
    record_id: String,
    tenant_id: String,
    issuer_ca_id: String,
    certificate_pem: String,
    serial: String,
    fingerprint: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    status: String,
    key_custody: String,
    created_at: DateTime<Utc>,
    retired_at: Option<DateTime<Utc>>,
    key_locator: Option<String>,
    encrypted_private_key: Option<surrealdb_types::Bytes>,
}

impl std::fmt::Debug for SealedRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedRow")
            .field("record_id", &self.record_id)
            .field("encrypted_private_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

fn custody_from(raw: &str) -> Result<CaKeyCustody, DbError> {
    raw.parse::<CaKeyCustody>().map_err(|_| {
        DbError::Serialization("saml_idp_credential has an unknown key_custody".into())
    })
}

impl CredentialRow {
    fn into_domain(self) -> Result<SamlIdpCredential, DbError> {
        Ok(SamlIdpCredential {
            id: parse_uuid(&self.record_id, ENTITY)?,
            tenant_id: parse_uuid(&self.tenant_id, "tenant")?,
            issuer_ca_id: parse_uuid(&self.issuer_ca_id, "issuing CA")?,
            certificate_pem: self.certificate_pem,
            serial: self.serial,
            fingerprint: self.fingerprint,
            not_before: self.not_before,
            not_after: self.not_after,
            status: SamlIdpCredentialStatus::from_wire(&self.status).ok_or_else(|| {
                DbError::Serialization("saml_idp_credential has an unknown status".into())
            })?,
            key_custody: custody_from(&self.key_custody)?,
            created_at: self.created_at,
            retired_at: self.retired_at,
        })
    }
}

impl SealedRow {
    fn into_domain(self) -> Result<SealedSamlIdpCredential, DbError> {
        let key = SealedSamlIdpKey {
            custody: custody_from(&self.key_custody)?,
            locator: self.key_locator,
            ciphertext: self.encrypted_private_key.map(|b| b.into_inner().to_vec()),
        };
        let credential = CredentialRow {
            record_id: self.record_id,
            tenant_id: self.tenant_id,
            issuer_ca_id: self.issuer_ca_id,
            certificate_pem: self.certificate_pem,
            serial: self.serial,
            fingerprint: self.fingerprint,
            not_before: self.not_before,
            not_after: self.not_after,
            status: self.status,
            key_custody: self.key_custody,
            created_at: self.created_at,
            retired_at: self.retired_at,
        }
        .into_domain()?;
        Ok(SealedSamlIdpCredential { credential, key })
    }
}

/// Why one attempt of [`SamlIdpCredentialRepository::promote`]'s transaction
/// failed. Its `Display` is the engine's own text for a datastore failure, which
/// is what the write-conflict retry reads.
enum PromoteFailure {
    NotFound,
    NotNext,
    OutsideWindow,
    Db(DbError),
}

impl std::fmt::Display for PromoteFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("the credential does not exist"),
            Self::NotNext => f.write_str("the credential is not the current next credential"),
            Self::OutsideWindow => f.write_str("the credential is outside its validity window"),
            Self::Db(error) => write!(f, "{error}"),
        }
    }
}

/// SurrealDB implementation of [`SamlIdpCredentialRepository`].
#[derive(Clone)]
pub struct SurrealSamlIdpCredentialRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> SurrealSamlIdpCredentialRepository<C> {
    /// Build the repository over a database handle.
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }

    async fn fetch(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<Option<SamlIdpCredential>> {
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {COLUMNS} FROM saml_idp_credential \
                 WHERE meta::id(id) = $id AND tenant_id = $tenant_id"
            ))
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<CredentialRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .map(|row| row.into_domain().map_err(AxiamError::from))
            .transpose()
    }
}

impl<C: Connection> SamlIdpCredentialRepository for SurrealSamlIdpCredentialRepository<C> {
    async fn create(&self, input: StoreSamlIdpCredential) -> AxiamResult<SamlIdpCredential> {
        if input.status == SamlIdpCredentialStatus::Retired {
            return Err(AxiamError::Validation {
                message: "a SAML IdP credential cannot be created retired".into(),
            });
        }
        let id = input.id;
        let tenant_id = input.tenant_id;
        let result = self
            .db
            .current()
            .query(
                "CREATE type::record('saml_idp_credential', $id) SET \
                 tenant_id = $tenant_id, issuer_ca_id = $issuer_ca_id, \
                 certificate_pem = $certificate_pem, serial = $serial, \
                 fingerprint = $fingerprint, not_before = $not_before, \
                 not_after = $not_after, status = $status, \
                 key_custody = $key_custody, key_locator = $key_locator, \
                 encrypted_private_key = $encrypted_private_key, \
                 created_at = time::now(), updated_at = time::now()",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("issuer_ca_id", input.issuer_ca_id.to_string()))
            .bind(("certificate_pem", input.certificate_pem))
            .bind(("serial", input.serial))
            .bind(("fingerprint", input.fingerprint))
            .bind(("not_before", input.not_before))
            .bind(("not_after", input.not_after))
            .bind(("status", input.status.as_str().to_owned()))
            .bind(("key_custody", input.key.custody.to_string()))
            .bind(("key_locator", input.key.locator))
            .bind((
                "encrypted_private_key",
                input.key.ciphertext.map(surrealdb_types::Bytes::from),
            ))
            .await
            .map_err(DbError::from)?;
        // The unique index over `slot` is what refuses a second active or next
        // credential for the tenant.
        result
            .check()
            .map_err(|e| classify_write_error(e, ENTITY))?;

        let created = self.fetch(tenant_id, id).await?;
        Ok(take_first_or_not_found(
            created.into_iter().collect(),
            ENTITY,
            &id.to_string(),
        )?)
    }

    async fn get(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<SamlIdpCredential> {
        let found = self.fetch(tenant_id, id).await?;
        Ok(take_first_or_not_found(
            found.into_iter().collect(),
            ENTITY,
            &id.to_string(),
        )?)
    }

    async fn get_active(&self, tenant_id: Uuid) -> AxiamResult<Option<SamlIdpCredential>> {
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {COLUMNS} FROM saml_idp_credential \
                 WHERE tenant_id = $tenant_id AND status = 'active'"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<CredentialRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .map(|row| row.into_domain().map_err(AxiamError::from))
            .transpose()
    }

    async fn get_active_sealed(
        &self,
        tenant_id: Uuid,
    ) -> AxiamResult<Option<SealedSamlIdpCredential>> {
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {SEALED_COLUMNS} FROM saml_idp_credential \
                 WHERE tenant_id = $tenant_id AND status = 'active'"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<SealedRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .map(|row| row.into_domain().map_err(AxiamError::from))
            .transpose()
    }

    async fn list(&self, tenant_id: Uuid) -> AxiamResult<Vec<SamlIdpCredential>> {
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {COLUMNS} FROM saml_idp_credential \
                 WHERE tenant_id = $tenant_id ORDER BY created_at ASC"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<CredentialRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(|row| row.into_domain().map_err(AxiamError::from))
            .collect()
    }

    async fn retire(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<SamlIdpCredential> {
        // The tenant guard is in the `WHERE`: a row of another tenant matches
        // nothing and reads back as `NotFound`. The key columns are cleared in
        // the same statement that takes the row out of its slot, so there is no
        // moment at which a retired credential still holds a key. A row that is
        // already retired is left exactly as it is.
        self.db
            .current()
            .query(
                "UPDATE type::record('saml_idp_credential', $id) SET \
                 status = 'retired', encrypted_private_key = NONE, key_locator = NONE, \
                 retired_at = time::now(), updated_at = time::now() \
                 WHERE tenant_id = $tenant_id AND status != 'retired'",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| classify_write_error(e, ENTITY))?;

        self.get(tenant_id, id).await
    }

    async fn promote(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        now: DateTime<Utc>,
    ) -> AxiamResult<SamlIdpCredentialPromotion> {
        #[derive(Debug, SurrealValue)]
        struct RetiredId {
            record_id: String,
        }

        // The whole rotation is one transaction. The checks come first and
        // `THROW`, so a promotion that cannot happen has written nothing; then
        // the old `active` leaves its slot (and its key is destroyed in the same
        // write, as `retire` does) *before* the `next` row takes the slot, which
        // is what keeps the UNIQUE `slot` index satisfied at every statement and
        // leaves no state with two signers or none. Statement numbers, counting
        // BEGIN: 0 BEGIN, 1 LET $row, 2-4 the three checks, 5 LET $retired,
        // 6 UPDATE, 7 SELECT, 8 COMMIT.
        //
        // A contended attempt aborts and commits nothing, so it is replayed
        // (`retry_on_write_conflict`); the replay sees the winner's state and
        // answers `Conflict`, which is how the loser of two concurrent
        // promotions is told.
        let attempt = || async {
            let mut result = self
                .db
                .current()
                .query(format!(
                    "BEGIN TRANSACTION; \
                     LET $row = (SELECT status, not_before, not_after FROM saml_idp_credential \
                         WHERE meta::id(id) = $id AND tenant_id = $tenant_id); \
                     IF array::len($row) == 0 {{ THROW '{DELETE_TARGET_MISSING}'; }}; \
                     IF $row[0].status != 'next' {{ THROW '{PROMOTE_NOT_NEXT}'; }}; \
                     IF $row[0].not_before > $now OR $row[0].not_after <= $now \
                         {{ THROW '{PROMOTE_OUTSIDE_WINDOW}'; }}; \
                     LET $retired = (UPDATE saml_idp_credential SET \
                         status = 'retired', encrypted_private_key = NONE, key_locator = NONE, \
                         retired_at = time::now(), updated_at = time::now() \
                         WHERE tenant_id = $tenant_id AND status = 'active'); \
                     UPDATE type::record('saml_idp_credential', $id) SET \
                         status = 'active', updated_at = time::now(); \
                     SELECT meta::id(id) AS record_id FROM $retired; \
                     COMMIT TRANSACTION"
                ))
                .bind(("id", id.to_string()))
                .bind(("tenant_id", tenant_id.to_string()))
                .bind(("now", now))
                .await
                .map_err(|e| PromoteFailure::Db(DbError::from(e)))?;

            let errors = result.take_errors();
            if !errors.is_empty() {
                // Every statement's error, not `check()`'s pick: a `THROW`
                // fires on its own slot while the rest report the generic
                // "not executed due to a failed transaction".
                let combined = errors
                    .into_values()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(if combined.contains(DELETE_TARGET_MISSING) {
                    PromoteFailure::NotFound
                } else if combined.contains(PROMOTE_NOT_NEXT) {
                    PromoteFailure::NotNext
                } else if combined.contains(PROMOTE_OUTSIDE_WINDOW) {
                    PromoteFailure::OutsideWindow
                } else if is_write_conflict(&combined) {
                    PromoteFailure::Db(DbError::Conflict(combined))
                } else {
                    PromoteFailure::Db(classify_write_error(combined, ENTITY))
                });
            }
            result
                .take::<Vec<RetiredId>>(7)
                .map_err(|e| PromoteFailure::Db(DbError::from(e)))
        };
        // Replayed while the engine reports a write conflict. The retry reads the
        // *engine's* text, so the attempt keeps its failure as a `PromoteFailure`
        // (whose `Display` carries it) and only the settled outcome becomes an
        // `AxiamError` — converted earlier, a conflict would already be the
        // payload-free `WriteContention` and never be retried.
        let retired = retry_on_write_conflict(attempt)
            .await
            .map_err(|failure| match failure {
                PromoteFailure::NotFound => AxiamError::from(DbError::NotFound {
                    entity: ENTITY.into(),
                    id: id.to_string(),
                }),
                PromoteFailure::NotNext => AxiamError::Conflict {
                    reason: "the credential is not the tenant's current `next` credential".into(),
                },
                PromoteFailure::OutsideWindow => AxiamError::Conflict {
                    reason: "the `next` credential is outside its validity window".into(),
                },
                PromoteFailure::Db(error) => AxiamError::from(error),
            })?;

        let active = self.get(tenant_id, id).await?;
        let retired = match retired.into_iter().next() {
            Some(row) => {
                let old = parse_uuid(&row.record_id, ENTITY).map_err(AxiamError::from)?;
                Some(self.get(tenant_id, old).await?)
            }
            None => None,
        };
        Ok(SamlIdpCredentialPromotion { active, retired })
    }
}

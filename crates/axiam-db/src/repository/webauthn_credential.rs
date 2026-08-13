//! SurrealDB implementation of [`WebauthnCredentialRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::id::new_id;
use axiam_core::models::webauthn_credential::{
    CreateWebauthnCredential, WebauthnCredential, WebauthnCredentialType,
};
use axiam_core::repository::WebauthnCredentialRepository;
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{CountRow, take_first_or_not_found};

#[derive(Debug, SurrealValue)]
struct WebauthnCredentialRow {
    tenant_id: String,
    user_id: String,
    credential_id: String,
    name: String,
    credential_type: String,
    passkey_json: String,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    // D6 (X3, wave 2): additive attestation metadata. `#[serde(default)]`-style
    // absence handling isn't applicable to `SurrealValue` the way it is to
    // `serde`, but the column itself is `option<..>`/`DEFAULT false` (schema
    // v35), so a row written before this column existed reads back as
    // `None`/`false` here regardless — the same "additive, no migration"
    // guarantee D6 requires, just enforced by the schema default rather than
    // a derive attribute.
    aaguid: Option<String>,
    attestation_format: Option<String>,
    attested: bool,
    authenticator_name: Option<String>,
}

#[derive(Debug, SurrealValue)]
struct WebauthnCredentialRowWithId {
    record_id: String,
    tenant_id: String,
    user_id: String,
    credential_id: String,
    name: String,
    credential_type: String,
    passkey_json: String,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    // D6 (X3, wave 2): see `WebauthnCredentialRow` above.
    aaguid: Option<String>,
    attestation_format: Option<String>,
    attested: bool,
    authenticator_name: Option<String>,
}

fn parse_credential_type(s: &str) -> Result<WebauthnCredentialType, DbError> {
    match s {
        "Passkey" => Ok(WebauthnCredentialType::Passkey),
        "SecurityKey" => Ok(WebauthnCredentialType::SecurityKey),
        other => Err(DbError::Migration(format!(
            "invalid credential_type: {other}"
        ))),
    }
}

/// Parse an optional stored AAGUID string. A `None` column reads back as
/// `None`; a corrupt (non-UUID) value is reported rather than silently
/// dropped, matching `parse_uuid`'s D-10 rationale for other UUID columns.
fn parse_optional_aaguid(s: Option<String>) -> Result<Option<Uuid>, DbError> {
    s.map(|s| crate::helpers::parse_uuid(&s, "aaguid"))
        .transpose()
}

fn row_to_credential(row: WebauthnCredentialRow, id: Uuid) -> Result<WebauthnCredential, DbError> {
    let tenant_id = Uuid::parse_str(&row.tenant_id)
        .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
    let user_id = Uuid::parse_str(&row.user_id)
        .map_err(|e| DbError::Migration(format!("invalid user UUID: {e}")))?;
    let credential_type = parse_credential_type(&row.credential_type)?;
    let aaguid = parse_optional_aaguid(row.aaguid)?;
    Ok(WebauthnCredential {
        id,
        tenant_id,
        user_id,
        credential_id: row.credential_id,
        name: row.name,
        credential_type,
        passkey_json: row.passkey_json,
        created_at: row.created_at,
        last_used_at: row.last_used_at,
        // D6 (X3, wave 2): read back whatever was recorded at registration
        // time. A pre-X3 row has no column value at all, which the schema
        // (v35) reads as None/false — the same "today's behavior unchanged"
        // guarantee the wave-1 model already documents.
        aaguid,
        attestation_format: row.attestation_format,
        attested: row.attested,
        authenticator_name: row.authenticator_name,
    })
}

impl WebauthnCredentialRowWithId {
    fn try_into_credential(self) -> Result<WebauthnCredential, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let user_id = Uuid::parse_str(&self.user_id)
            .map_err(|e| DbError::Migration(format!("invalid user UUID: {e}")))?;
        let credential_type = parse_credential_type(&self.credential_type)?;
        let aaguid = parse_optional_aaguid(self.aaguid)?;
        Ok(WebauthnCredential {
            id,
            tenant_id,
            user_id,
            credential_id: self.credential_id,
            name: self.name,
            credential_type,
            passkey_json: self.passkey_json,
            created_at: self.created_at,
            last_used_at: self.last_used_at,
            // D6 (X3, wave 2): see the equivalent comment in `row_to_credential`.
            aaguid,
            attestation_format: self.attestation_format,
            attested: self.attested,
            authenticator_name: self.authenticator_name,
        })
    }
}

/// SurrealDB implementation of the WebAuthn credential repository.
#[derive(Clone)]
pub struct SurrealWebauthnCredentialRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> SurrealWebauthnCredentialRepository<C> {
    /// Create a new repository backed by the given SurrealDB client.
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        let db = db.into();
        Self { db }
    }
}

impl<C: Connection> WebauthnCredentialRepository for SurrealWebauthnCredentialRepository<C> {
    async fn create(&self, input: CreateWebauthnCredential) -> AxiamResult<WebauthnCredential> {
        let id = new_id();
        let id_str = id.to_string();

        let result = self
            .db
            .current()
            .query(
                "CREATE type::record('webauthn_credential', $id) SET \
                 tenant_id = $tenant_id, \
                 user_id = $user_id, \
                 credential_id = $credential_id, \
                 name = $name, \
                 credential_type = $credential_type, \
                 passkey_json = $passkey_json, \
                 aaguid = $aaguid, \
                 attestation_format = $attestation_format, \
                 attested = $attested, \
                 authenticator_name = $authenticator_name",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("user_id", input.user_id.to_string()))
            .bind(("credential_id", input.credential_id))
            .bind(("name", input.name))
            .bind((
                "credential_type",
                input.credential_type.as_str().to_string(),
            ))
            .bind(("passkey_json", input.passkey_json))
            .bind(("aaguid", input.aaguid.map(|u| u.to_string())))
            .bind(("attestation_format", input.attestation_format))
            .bind(("attested", input.attested))
            .bind(("authenticator_name", input.authenticator_name))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<WebauthnCredentialRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "webauthn_credential", &id_str)?;

        row_to_credential(row, id).map_err(Into::into)
    }

    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<WebauthnCredential> {
        let id_str = id.to_string();

        let mut result = self
            .db
            .current()
            .query(
                "SELECT * FROM type::record('webauthn_credential', $id) \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<WebauthnCredentialRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "webauthn_credential", &id_str)?;

        row_to_credential(row, id).map_err(Into::into)
    }

    async fn list_by_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AxiamResult<Vec<WebauthnCredential>> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM webauthn_credential \
                 WHERE tenant_id = $tenant_id \
                 AND user_id = $user_id \
                 ORDER BY created_at DESC",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<WebauthnCredentialRowWithId> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(|r| r.try_into_credential().map_err(Into::into))
            .collect()
    }

    /// X3 wave 3 (D9): every credential in the tenant, across all users —
    /// the compliance report's source list. Mirrors `list_by_user` minus the
    /// `user_id` filter.
    async fn list_by_tenant(&self, tenant_id: Uuid) -> AxiamResult<Vec<WebauthnCredential>> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM webauthn_credential \
                 WHERE tenant_id = $tenant_id \
                 ORDER BY created_at DESC",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<WebauthnCredentialRowWithId> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(|r| r.try_into_credential().map_err(Into::into))
            .collect()
    }

    async fn update_last_used(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        self.db
            .current()
            .query(
                "UPDATE type::record('webauthn_credential', $id) SET \
                 last_used_at = time::now() \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        Ok(())
    }

    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        self.db
            .current()
            .query(
                "DELETE type::record('webauthn_credential', $id) \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        Ok(())
    }

    async fn count_by_user(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<u64> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM webauthn_credential \
                 WHERE tenant_id = $tenant_id \
                 AND user_id = $user_id \
                 GROUP ALL",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<CountRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows.first().map(|r| r.total).unwrap_or(0))
    }
}

//! SurrealDB implementation of [`WebauthnCredentialRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::webauthn_credential::{
    CreateWebauthnCredential, WebauthnCredential, WebauthnCredentialType,
};
use axiam_core::repository::WebauthnCredentialRepository;
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

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
}

#[derive(Debug, SurrealValue)]
struct CountRow {
    total: u64,
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

fn row_to_credential(row: WebauthnCredentialRow, id: Uuid) -> Result<WebauthnCredential, DbError> {
    let tenant_id = Uuid::parse_str(&row.tenant_id)
        .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
    let user_id = Uuid::parse_str(&row.user_id)
        .map_err(|e| DbError::Migration(format!("invalid user UUID: {e}")))?;
    let credential_type = parse_credential_type(&row.credential_type)?;
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
        })
    }
}

/// SurrealDB implementation of the WebAuthn credential repository.
#[derive(Clone)]
pub struct SurrealWebauthnCredentialRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> SurrealWebauthnCredentialRepository<C> {
    /// Create a new repository backed by the given SurrealDB client.
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> WebauthnCredentialRepository for SurrealWebauthnCredentialRepository<C> {
    async fn create(&self, input: CreateWebauthnCredential) -> AxiamResult<WebauthnCredential> {
        let id = Uuid::new_v4();
        let id_str = id.to_string();

        let result = self
            .db
            .query(
                "CREATE type::record('webauthn_credential', $id) SET \
                 tenant_id = $tenant_id, \
                 user_id = $user_id, \
                 credential_id = $credential_id, \
                 name = $name, \
                 credential_type = $credential_type, \
                 passkey_json = $passkey_json",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("user_id", input.user_id.to_string()))
            .bind(("credential_id", input.credential_id))
            .bind(("name", input.name))
            .bind(("credential_type", format!("{:?}", input.credential_type)))
            .bind(("passkey_json", input.passkey_json))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<WebauthnCredentialRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "webauthn_credential".into(),
            id: id_str,
        })?;

        row_to_credential(row, id).map_err(Into::into)
    }

    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<WebauthnCredential> {
        let id_str = id.to_string();

        let mut result = self
            .db
            .query(
                "SELECT * FROM type::record('webauthn_credential', $id) \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<WebauthnCredentialRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "webauthn_credential".into(),
            id: id_str,
        })?;

        row_to_credential(row, id).map_err(Into::into)
    }

    async fn list_by_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AxiamResult<Vec<WebauthnCredential>> {
        let mut result = self
            .db
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

    async fn update_last_used(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        self.db
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

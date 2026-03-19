//! SurrealDB implementation of [`EmailTemplateRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::email_template::{EmailTemplate, SetEmailTemplate, TemplateKind};
use axiam_core::models::settings::SettingsScope;
use axiam_core::repository::EmailTemplateRepository;
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

// -----------------------------------------------------------------------
// Row structs
// -----------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct TemplateRow {
    scope: String,
    scope_id: String,
    kind: String,
    subject: String,
    html_body: String,
    text_body: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct TemplateRowWithId {
    record_id: String,
    scope: String,
    scope_id: String,
    kind: String,
    subject: String,
    html_body: String,
    text_body: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TemplateRowWithId {
    fn try_into_domain(self) -> Result<EmailTemplate, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("bad UUID: {e}")))?;
        let scope_id = Uuid::parse_str(&self.scope_id)
            .map_err(|e| DbError::Migration(format!("bad UUID: {e}")))?;
        let scope: SettingsScope = self
            .scope
            .parse()
            .map_err(|e: String| DbError::Migration(e))?;
        let kind: TemplateKind = self
            .kind
            .parse()
            .map_err(|e: String| DbError::Migration(e))?;

        Ok(EmailTemplate {
            id,
            scope,
            scope_id,
            kind,
            subject: self.subject,
            html_body: self.html_body,
            text_body: self.text_body,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

// -----------------------------------------------------------------------
// Repository
// -----------------------------------------------------------------------

#[derive(Clone)]
pub struct SurrealEmailTemplateRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> SurrealEmailTemplateRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }

    fn deterministic_id(scope: &str, scope_id: &str, kind: &str) -> String {
        Uuid::new_v5(
            &Uuid::NAMESPACE_OID,
            format!("tmpl:{scope}:{scope_id}:{kind}").as_bytes(),
        )
        .to_string()
    }

    async fn upsert_template(
        &self,
        scope: SettingsScope,
        scope_id: Uuid,
        input: &SetEmailTemplate,
    ) -> Result<EmailTemplate, DbError> {
        let scope_str = scope.to_string();
        let scope_id_str = scope_id.to_string();
        let kind_str = input.kind.to_string();
        let id = Self::deterministic_id(&scope_str, &scope_id_str, &kind_str);

        let result = self
            .db
            .query(
                "UPSERT type::record('email_template', $id) SET \
                 scope = $scope, scope_id = $scope_id, \
                 kind = $kind, subject = $subject, \
                 html_body = $html_body, text_body = $text_body, \
                 created_at = created_at OR time::now(), \
                 updated_at = time::now()",
            )
            .bind(("id", id.clone()))
            .bind(("scope", scope_str))
            .bind(("scope_id", scope_id_str))
            .bind(("kind", kind_str))
            .bind(("subject", input.subject.clone()))
            .bind(("html_body", input.html_body.clone()))
            .bind(("text_body", input.text_body.clone()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<TemplateRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "email_template".into(),
            id,
        })?;

        let det_id = Uuid::parse_str(&Self::deterministic_id(
            &row.scope,
            &row.scope_id,
            &row.kind,
        ))
        .unwrap();

        Ok(EmailTemplate {
            id: det_id,
            scope,
            scope_id,
            kind: input.kind,
            subject: row.subject,
            html_body: row.html_body,
            text_body: row.text_body,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn fetch_template(
        &self,
        scope: &str,
        scope_id: &str,
        kind: &str,
    ) -> Result<Option<EmailTemplate>, DbError> {
        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM email_template \
                 WHERE scope = $scope \
                   AND scope_id = $scope_id \
                   AND kind = $kind",
            )
            .bind(("scope", scope.to_string()))
            .bind(("scope_id", scope_id.to_string()))
            .bind(("kind", kind.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<TemplateRowWithId> = result.take(0).map_err(DbError::from)?;
        match rows.into_iter().next() {
            Some(row) => Ok(Some(row.try_into_domain()?)),
            None => Ok(None),
        }
    }

    async fn list_templates(
        &self,
        scope: &str,
        scope_id: &str,
    ) -> Result<Vec<EmailTemplate>, DbError> {
        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM email_template \
                 WHERE scope = $scope AND scope_id = $scope_id \
                 ORDER BY kind ASC",
            )
            .bind(("scope", scope.to_string()))
            .bind(("scope_id", scope_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<TemplateRowWithId> = result.take(0).map_err(DbError::from)?;
        rows.into_iter().map(|r| r.try_into_domain()).collect()
    }

    async fn delete_template(
        &self,
        scope: &str,
        scope_id: &str,
        kind: &str,
    ) -> Result<(), DbError> {
        self.db
            .query(
                "DELETE email_template \
                 WHERE scope = $scope \
                   AND scope_id = $scope_id \
                   AND kind = $kind",
            )
            .bind(("scope", scope.to_string()))
            .bind(("scope_id", scope_id.to_string()))
            .bind(("kind", kind.to_string()))
            .await
            .map_err(DbError::from)?;
        Ok(())
    }
}

impl<C: Connection> EmailTemplateRepository for SurrealEmailTemplateRepository<C> {
    async fn get_org_template(
        &self,
        org_id: Uuid,
        kind: TemplateKind,
    ) -> AxiamResult<Option<EmailTemplate>> {
        Ok(self
            .fetch_template("org", &org_id.to_string(), &kind.to_string())
            .await?)
    }

    async fn set_org_template(
        &self,
        org_id: Uuid,
        input: SetEmailTemplate,
    ) -> AxiamResult<EmailTemplate> {
        Ok(self
            .upsert_template(SettingsScope::Org, org_id, &input)
            .await?)
    }

    async fn delete_org_template(&self, org_id: Uuid, kind: TemplateKind) -> AxiamResult<()> {
        Ok(self
            .delete_template("org", &org_id.to_string(), &kind.to_string())
            .await?)
    }

    async fn list_org_templates(&self, org_id: Uuid) -> AxiamResult<Vec<EmailTemplate>> {
        Ok(self.list_templates("org", &org_id.to_string()).await?)
    }

    async fn get_tenant_template(
        &self,
        tenant_id: Uuid,
        kind: TemplateKind,
    ) -> AxiamResult<Option<EmailTemplate>> {
        Ok(self
            .fetch_template("tenant", &tenant_id.to_string(), &kind.to_string())
            .await?)
    }

    async fn set_tenant_template(
        &self,
        tenant_id: Uuid,
        input: SetEmailTemplate,
    ) -> AxiamResult<EmailTemplate> {
        Ok(self
            .upsert_template(SettingsScope::Tenant, tenant_id, &input)
            .await?)
    }

    async fn delete_tenant_template(&self, tenant_id: Uuid, kind: TemplateKind) -> AxiamResult<()> {
        Ok(self
            .delete_template("tenant", &tenant_id.to_string(), &kind.to_string())
            .await?)
    }

    async fn list_tenant_templates(&self, tenant_id: Uuid) -> AxiamResult<Vec<EmailTemplate>> {
        Ok(self
            .list_templates("tenant", &tenant_id.to_string())
            .await?)
    }
}

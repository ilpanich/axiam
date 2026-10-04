//! SurrealDB implementation of [`TenantRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::id::new_id;
use axiam_core::models::tenant::{CreateTenant, Tenant, TenantKind, TenantStatus, UpdateTenant};
use axiam_core::repository::{PaginatedResult, Pagination, TenantRepository};
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{CountRow, classify_write_error, paginate, take_first_or_not_found};

fn parse_status(s: &str) -> Result<TenantStatus, DbError> {
    match s {
        "Active" => Ok(TenantStatus::Active),
        "Suspended" => Ok(TenantStatus::Suspended),
        other => Err(DbError::Migration(format!(
            "unknown tenant status: {other}"
        ))),
    }
}

fn status_to_str(s: &TenantStatus) -> &'static str {
    match s {
        TenantStatus::Active => "Active",
        TenantStatus::Suspended => "Suspended",
    }
}

/// An absent or empty `kind` is [`TenantKind::Standard`].
///
/// Every tenant row written before organization scope existed has no `kind` at
/// all, and every one of them is an ordinary tenant — so the absent case is not
/// a parse failure, it is the answer. An *unrecognised* value is still an
/// error: that is a row from a future version, and guessing at it would be
/// guessing about an authorization boundary.
fn parse_kind(s: Option<&str>) -> Result<TenantKind, DbError> {
    match s.unwrap_or("").trim() {
        "" | "standard" => Ok(TenantKind::Standard),
        "organization" => Ok(TenantKind::Organization),
        other => Err(DbError::Migration(format!("unknown tenant kind: {other}"))),
    }
}

fn kind_to_str(k: TenantKind) -> &'static str {
    match k {
        TenantKind::Standard => "standard",
        TenantKind::Organization => "organization",
    }
}

/// DB-side row struct for queries where the UUID is already known.
#[derive(Debug, SurrealValue)]
struct TenantRow {
    organization_id: String,
    name: String,
    slug: String,
    status: String,
    #[surreal(default)]
    kind: Option<String>,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TenantRow {
    fn into_tenant(self, id: Uuid) -> Result<Tenant, DbError> {
        let org_id = Uuid::parse_str(&self.organization_id)
            .map_err(|e| DbError::Migration(format!("invalid org UUID: {e}")))?;
        Ok(Tenant {
            id,
            organization_id: org_id,
            name: self.name,
            slug: self.slug,
            status: parse_status(&self.status)?,
            kind: parse_kind(self.kind.as_deref())?,
            metadata: self.metadata,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// DB-side row struct that includes the record ID via `meta::id(id)`.
#[derive(Debug, SurrealValue)]
struct TenantRowWithId {
    record_id: String,
    organization_id: String,
    name: String,
    slug: String,
    status: String,
    #[surreal(default)]
    kind: Option<String>,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TenantRowWithId {
    fn try_into_tenant(self) -> Result<Tenant, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let org_id = Uuid::parse_str(&self.organization_id)
            .map_err(|e| DbError::Migration(format!("invalid org UUID: {e}")))?;
        Ok(Tenant {
            id,
            organization_id: org_id,
            name: self.name,
            slug: self.slug,
            status: parse_status(&self.status)?,
            kind: parse_kind(self.kind.as_deref())?,
            metadata: self.metadata,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// SurrealDB implementation of the Tenant repository.
#[derive(Clone)]
pub struct SurrealTenantRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> SurrealTenantRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        let db = db.into();
        Self { db }
    }
}

impl<C: Connection> TenantRepository for SurrealTenantRepository<C> {
    async fn create(&self, input: CreateTenant) -> AxiamResult<Tenant> {
        let id = new_id();
        let id_str = id.to_string();
        let org_id_str = input.organization_id.to_string();
        let metadata = input
            .metadata
            .unwrap_or(serde_json::Value::Object(Default::default()));

        // Create tenant record and relate to organization in one query.
        // RELATE requires literal record-id syntax, so we embed UUIDs
        // directly in the RELATE portion (they are safe — UUID format).
        //
        // An organization tenant also claims `organization_scope:<org_id>`,
        // whose record id IS the constraint that there is only one of them. A
        // second attempt fails on that CREATE rather than quietly producing a
        // second place organization-level principals could live — see
        // `SCHEMA_V50` for why this is a marker row and not a partial unique
        // index.
        let claim_scope = if input.kind.is_organization() {
            " CREATE type::record('organization_scope', $org_id) \
              SET tenant_id = $id;"
        } else {
            ""
        };
        let query = format!(
            "CREATE type::record('tenant', $id) SET \
             organization_id = $org_id, \
             name = $name, slug = $slug, \
             status = 'Active', \
             kind = $kind, \
             metadata = $metadata; \
             RELATE organization:`{org_id_str}` \
             -> has_tenant -> tenant:`{id_str}`;{claim_scope}"
        );

        let result = self
            .db
            .current()
            .query(query)
            .bind(("id", id_str.clone()))
            .bind(("org_id", org_id_str))
            .bind(("name", input.name))
            .bind(("slug", input.slug))
            .bind(("kind", kind_to_str(input.kind)))
            .bind(("metadata", metadata))
            .await
            .map_err(DbError::from)?;

        // A duplicate (organization_id, slug) trips the `idx_tenant_org_slug`
        // unique index. Left unclassified it becomes `DbError::Migration`, which
        // the API layer maps to a bare 500 `{"error":"internal_error"}` — so
        // re-running any provisioning script answers "something broke" for a
        // system that is in fact perfectly fine, and the documented 409 branch
        // of `scripts/e2e-bootstrap.sh` was dead code.
        //
        // Per D-09 the marker matching lives in `helpers::classify_write_error`
        // and nowhere else, so that a marker added there reaches every call
        // site at once.
        let mut result = result
            .check()
            .map_err(|e| classify_write_error(e, "tenant"))?;

        // Statement 0 is the CREATE, statement 1 is the RELATE.
        let rows: Vec<TenantRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "tenant", &id_str)?;

        Ok(row.into_tenant(id)?)
    }

    async fn get_by_id(&self, id: Uuid) -> AxiamResult<Tenant> {
        let id_str = id.to_string();

        let mut result = self
            .db
            .current()
            .query("SELECT * FROM type::record('tenant', $id)")
            .bind(("id", id_str.clone()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<TenantRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "tenant", &id_str)?;

        Ok(row.into_tenant(id)?)
    }

    async fn get_by_slug(&self, organization_id: Uuid, slug: &str) -> AxiamResult<Tenant> {
        let org_id_str = organization_id.to_string();
        let slug_owned = slug.to_string();

        let mut result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM tenant \
                 WHERE organization_id = $org_id AND slug = $slug",
            )
            .bind(("org_id", org_id_str))
            .bind(("slug", slug_owned))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<TenantRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(
            rows,
            "tenant",
            &format!("org={organization_id},slug={slug}"),
        )?;

        Ok(row.try_into_tenant()?)
    }

    async fn get_organization_tenant(&self, organization_id: Uuid) -> AxiamResult<Tenant> {
        let org_id_str = organization_id.to_string();

        let mut result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM tenant \
                 WHERE organization_id = $org_id AND kind = 'organization'",
            )
            .bind(("org_id", org_id_str))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<TenantRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(
            rows,
            "tenant",
            &format!("org={organization_id},kind=organization"),
        )?;

        Ok(row.try_into_tenant()?)
    }

    async fn update(&self, id: Uuid, input: UpdateTenant) -> AxiamResult<Tenant> {
        let id_str = id.to_string();

        let mut sets = Vec::new();
        if input.name.is_some() {
            sets.push("name = $name");
        }
        if input.slug.is_some() {
            sets.push("slug = $slug");
        }
        if input.status.is_some() {
            sets.push("status = $status");
        }
        if input.metadata.is_some() {
            sets.push("metadata = $metadata");
        }
        sets.push("updated_at = time::now()");

        let query = format!("UPDATE type::record('tenant', $id) SET {}", sets.join(", "));

        let db = self.db.current();
        let mut builder = db.query(&query).bind(("id", id_str.clone()));

        if let Some(name) = input.name {
            builder = builder.bind(("name", name));
        }
        if let Some(slug) = input.slug {
            builder = builder.bind(("slug", slug));
        }
        if let Some(status) = input.status {
            builder = builder.bind(("status", status_to_str(&status).to_string()));
        }
        if let Some(metadata) = input.metadata {
            builder = builder.bind(("metadata", metadata));
        }

        let result = builder.await.map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<TenantRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "tenant", &id_str)?;

        Ok(row.into_tenant(id)?)
    }

    async fn delete(&self, id: Uuid) -> AxiamResult<()> {
        // The tenant's SAML service providers go with it too (T23.2.1, G-2): a
        // registry of where this tenant's assertions may be delivered has no
        // meaning, and no business surviving, without the tenant.
        //
        // So does its SAML IdP signing credential (T23.2.1, D-21): a sealed
        // private key for a tenant that no longer exists is key material
        // nobody can account for, and it goes in the same transaction.
        //
        // And so do its pending SAML `AuthnRequest`s (T23.2.3, schema v73):
        // short-lived, but a row naming a deleted tenant's SP and ACS URL is
        // nothing a later tenant should be able to resume.
        //
        // And its SAML single-logout state (T23.2.4, schema v76): the participant
        // rows hold the `NameID` each SP was given (an email address at an
        // `emailAddress` SP) and the logout runs the chain of a session that no
        // longer has a tenant. Neither is anything a later tenant may resume.
        //
        // And its SSF streams and their buffered events (T23.5.2, schema v77):
        // a stream holds a sealed credential to a receiver and a buffered event
        // may hold a subject's email address; neither outlives the tenant.
        //
        // The tenant's directory configuration goes with it (T23.3.1, G-3): it
        // holds an encrypted service-account credential for the tenant's
        // directory, and a deleted tenant must not leave that ciphertext
        // behind. Its sync state (T23.3.5, schema v75: a watermark, a server
        // identity, account ids) goes in the same transaction: the job must not
        // find a deleted tenant's state, and a row naming accounts of a tenant
        // that no longer exists has no business surviving it. Everything is one
        // query, so the deletes commit or roll back
        // together. (The broader cascade is issue #523.)
        //
        // F4 P23W2-02: and a transaction that rolled back is an error. The
        // driver reports a failed statement inside the response, not from
        // `.await`, so without `check` a cancelled delete answered `Ok` — the
        // handler then answered `204` and wrote a "tenant deleted" record for
        // a tenant that still existed, with its encrypted bind secret.
        self.db
            .current()
            .query(
                "BEGIN TRANSACTION; \
                 DELETE directory_config WHERE tenant_id = $id; \
                 DELETE directory_sync_state WHERE tenant_id = $id; \
                 DELETE saml_service_provider WHERE tenant_id = $id; \
                 DELETE saml_idp_credential WHERE tenant_id = $id; \
                 DELETE saml_authn_request WHERE tenant_id = $id; \
                 DELETE saml_sp_session WHERE tenant_id = $id; \
                 DELETE saml_logout_run WHERE tenant_id = $id; \
                 DELETE ssf_event_buffer WHERE tenant_id = $id; \
                 DELETE ssf_step_up WHERE tenant_id = $id; \
                 DELETE ssf_stream WHERE tenant_id = $id; \
                 DELETE type::record('tenant', $id); \
                 COMMIT TRANSACTION;",
            )
            .bind(("id", id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(DbError::from)?;

        Ok(())
    }

    async fn list_by_organization(
        &self,
        organization_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<Tenant>> {
        let org_id_str = organization_id.to_string();

        let mut count_result = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM tenant \
                 WHERE organization_id = $org_id GROUP ALL",
            )
            .bind(("org_id", org_id_str.clone()))
            .await
            .map_err(DbError::from)?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;

        let mut result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM tenant \
                 WHERE organization_id = $org_id \
                 ORDER BY created_at ASC \
                 LIMIT $limit START $offset",
            )
            .bind(("org_id", org_id_str))
            .bind(("limit", pagination.limit))
            .bind(("offset", pagination.offset))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<TenantRowWithId> = result.take(0).map_err(DbError::from)?;

        let items = rows
            .into_iter()
            .map(|row| row.try_into_tenant())
            .collect::<Result<Vec<_>, DbError>>()?;

        Ok(paginate(items, count_rows, &pagination))
    }
}

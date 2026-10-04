//! SurrealDB implementation of [`SamlServiceProviderRepository`] (G-2, T23.2.1).
//!
//! One row per registered service provider, tenant-scoped; `(tenant_id,
//! entity_id)` is unique in the datastore (`idx_saml_sp_tenant_entity`), which
//! is what turns a concurrent double registration into `AlreadyExists`.
//!
//! The two structured lists — the ACS allow-list and the attribute mapping
//! table — are stored as JSON text columns (the pattern `oidc_cimd_json` set),
//! because they are written, read and replaced whole and never queried by
//! member. Every scalar is a typed `SCHEMAFULL` column. A row whose JSON cannot
//! be read is a **serialization error**, not an empty list: an SP that silently
//! lost its ACS allow-list would be one nobody could sign in to, and one that
//! lost its attribute mappings would send assertions without the attributes the
//! SP relies on.
//!
//! The repository does not validate; see the trait docs.
//!
//! # Delete is a cascade, in one transaction
//!
//! Removing a service provider removes what the datastore keeps *for* it
//! ([`SP_DELETE_CASCADE`]): its pending `AuthnRequest` rows today, and — added
//! by **T23.2.4**, in the same constant, so the same transaction — the
//! `saml_sp_session` rows D-37 keeps per SP. A registration that outlived its
//! delete in a side table would let a stale participation drive a logout
//! (T-366).

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::id::new_id;
use axiam_core::models::saml_sp::{
    AcsEndpoint, AttributeMapping, NameIdFormat, SamlBinding, SamlServiceProvider,
    SamlServiceProviderInput,
};
use axiam_core::repository::{PaginatedResult, Pagination, SamlServiceProviderRepository};
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{
    CountRow, classify_write_error, map_delete_errors, paginate, parse_uuid, search_bind,
    search_filter, take_first_or_not_found,
};

const ENTITY: &str = "saml_service_provider";

/// Every column, projected explicitly.
const COLUMNS: &str = "meta::id(id) AS record_id, tenant_id, enabled, display_name, \
    entity_id, acs_urls_json, slo_url, slo_binding, name_id_format, sign_responses, \
    encrypt_assertions, sp_signing_cert_pem, sp_encryption_cert_pem, \
    want_authn_requests_signed, allow_idp_initiated, attribute_mappings_json, \
    allowed_groups, created_at, updated_at";

#[derive(Debug, SurrealValue)]
struct SpRow {
    record_id: String,
    tenant_id: String,
    enabled: bool,
    display_name: String,
    entity_id: String,
    acs_urls_json: String,
    slo_url: Option<String>,
    slo_binding: Option<String>,
    name_id_format: String,
    sign_responses: bool,
    encrypt_assertions: bool,
    sp_signing_cert_pem: Option<String>,
    sp_encryption_cert_pem: Option<String>,
    want_authn_requests_signed: bool,
    allow_idp_initiated: bool,
    attribute_mappings_json: String,
    allowed_groups: Vec<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl SpRow {
    fn into_domain(self) -> Result<SamlServiceProvider, DbError> {
        let acs_urls: Vec<AcsEndpoint> =
            serde_json::from_str(&self.acs_urls_json).map_err(|_| {
                DbError::Serialization("saml_service_provider acs_urls_json is unreadable".into())
            })?;
        let attribute_mappings: Vec<AttributeMapping> =
            serde_json::from_str(&self.attribute_mappings_json).map_err(|_| {
                DbError::Serialization(
                    "saml_service_provider attribute_mappings_json is unreadable".into(),
                )
            })?;
        let slo_binding = match self.slo_binding.as_deref() {
            None => None,
            Some(raw) => Some(SamlBinding::from_wire(raw).ok_or_else(|| {
                DbError::Serialization("saml_service_provider has an unknown slo_binding".into())
            })?),
        };
        let name_id_format = NameIdFormat::from_wire(&self.name_id_format).ok_or_else(|| {
            DbError::Serialization("saml_service_provider has an unknown name_id_format".into())
        })?;
        let allowed_groups = self
            .allowed_groups
            .iter()
            .map(|g| parse_uuid(g, "allowed group"))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SamlServiceProvider {
            id: parse_uuid(&self.record_id, ENTITY)?,
            tenant_id: parse_uuid(&self.tenant_id, "tenant")?,
            enabled: self.enabled,
            display_name: self.display_name,
            entity_id: self.entity_id,
            acs_urls,
            slo_url: self.slo_url,
            slo_binding,
            name_id_format,
            sign_responses: self.sign_responses,
            encrypt_assertions: self.encrypt_assertions,
            sp_signing_cert_pem: self.sp_signing_cert_pem,
            sp_encryption_cert_pem: self.sp_encryption_cert_pem,
            want_authn_requests_signed: self.want_authn_requests_signed,
            allow_idp_initiated: self.allow_idp_initiated,
            attribute_mappings,
            allowed_groups,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// The bound values of one write, shared by `create` and `update`.
struct Bound {
    acs_urls_json: String,
    attribute_mappings_json: String,
    allowed_groups: Vec<String>,
}

fn bound(input: &SamlServiceProviderInput) -> AxiamResult<Bound> {
    let to_json = |what: &str, value: Result<String, serde_json::Error>| {
        value.map_err(|_| AxiamError::Validation {
            message: format!("{what} could not be serialised"),
        })
    };
    Ok(Bound {
        acs_urls_json: to_json("acs_urls", serde_json::to_string(&input.acs_urls))?,
        attribute_mappings_json: to_json(
            "attribute_mappings",
            serde_json::to_string(&input.attribute_mappings),
        )?,
        allowed_groups: input.allowed_groups.iter().map(Uuid::to_string).collect(),
    })
}

/// The `SET` clause every write shares.
const SET_CLAUSE: &str = "enabled = $enabled, display_name = $display_name, \
    entity_id = $entity_id, acs_urls_json = $acs_urls_json, slo_url = $slo_url, \
    slo_binding = $slo_binding, name_id_format = $name_id_format, \
    sign_responses = $sign_responses, encrypt_assertions = $encrypt_assertions, \
    sp_signing_cert_pem = $sp_signing_cert_pem, \
    sp_encryption_cert_pem = $sp_encryption_cert_pem, \
    want_authn_requests_signed = $want_authn_requests_signed, \
    allow_idp_initiated = $allow_idp_initiated, \
    attribute_mappings_json = $attribute_mappings_json, \
    allowed_groups = $allowed_groups";

/// What a service provider's delete removes besides the row itself, as
/// SurrealQL run inside the delete's transaction. Every statement is keyed on
/// `$tenant_id` and `$id` (the SP's record id, as the string those tables store
/// in `sp_id`).
///
/// **T23.2.4 adds its statement here** — `DELETE saml_sp_session WHERE
/// tenant_id = $tenant_id AND sp_id = $id;` — in the commit that creates the
/// table, so the cascade and the table arrive together and the delete test
/// (`deleting_an_sp_removes_what_the_datastore_holds_for_it`) is extended with
/// it. Nothing else may be written for an SP outside this constant without
/// extending it.
const SP_DELETE_CASCADE: &str = "\
    DELETE saml_authn_request WHERE tenant_id = $tenant_id AND sp_id = $id; \
    ";

/// SurrealDB implementation of [`SamlServiceProviderRepository`].
#[derive(Clone)]
pub struct SurrealSamlServiceProviderRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> SurrealSamlServiceProviderRepository<C> {
    /// Build the repository over a database handle.
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }

    async fn fetch(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<Option<SamlServiceProvider>> {
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {COLUMNS} FROM saml_service_provider \
                 WHERE meta::id(id) = $id AND tenant_id = $tenant_id"
            ))
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<SpRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .map(|row| row.into_domain().map_err(AxiamError::from))
            .transpose()
    }
}

impl<C: Connection> SamlServiceProviderRepository for SurrealSamlServiceProviderRepository<C> {
    async fn create(
        &self,
        tenant_id: Uuid,
        input: SamlServiceProviderInput,
    ) -> AxiamResult<SamlServiceProvider> {
        let values = bound(&input)?;
        let id = new_id();
        let result = self
            .db
            .current()
            .query(format!(
                "CREATE type::record('saml_service_provider', $id) SET \
                 tenant_id = $tenant_id, {SET_CLAUSE}, \
                 created_at = time::now(), updated_at = time::now()"
            ))
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("enabled", input.enabled))
            .bind(("display_name", input.display_name))
            .bind(("entity_id", input.entity_id))
            .bind(("acs_urls_json", values.acs_urls_json))
            .bind(("slo_url", input.slo_url))
            .bind((
                "slo_binding",
                input.slo_binding.map(|b| b.as_str().to_owned()),
            ))
            .bind(("name_id_format", input.name_id_format.as_str().to_owned()))
            .bind(("sign_responses", input.sign_responses))
            .bind(("encrypt_assertions", input.encrypt_assertions))
            .bind(("sp_signing_cert_pem", input.sp_signing_cert_pem))
            .bind(("sp_encryption_cert_pem", input.sp_encryption_cert_pem))
            .bind((
                "want_authn_requests_signed",
                input.want_authn_requests_signed,
            ))
            .bind(("allow_idp_initiated", input.allow_idp_initiated))
            .bind(("attribute_mappings_json", values.attribute_mappings_json))
            .bind(("allowed_groups", values.allowed_groups))
            .await
            .map_err(DbError::from)?;
        // The unique index on (tenant_id, entity_id) is what makes a second
        // registration of the same entity id an `AlreadyExists`.
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

    async fn get(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<SamlServiceProvider> {
        let found = self.fetch(tenant_id, id).await?;
        Ok(take_first_or_not_found(
            found.into_iter().collect(),
            ENTITY,
            &id.to_string(),
        )?)
    }

    async fn get_by_entity_id(
        &self,
        tenant_id: Uuid,
        entity_id: &str,
    ) -> AxiamResult<Option<SamlServiceProvider>> {
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {COLUMNS} FROM saml_service_provider \
                 WHERE tenant_id = $tenant_id AND entity_id = $entity_id"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("entity_id", entity_id.to_owned()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<SpRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .map(|row| row.into_domain().map_err(AxiamError::from))
            .transpose()
    }

    async fn list(&self, tenant_id: Uuid) -> AxiamResult<Vec<SamlServiceProvider>> {
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {COLUMNS} FROM saml_service_provider \
                 WHERE tenant_id = $tenant_id ORDER BY created_at ASC"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<SpRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(|row| row.into_domain().map_err(AxiamError::from))
            .collect()
    }

    async fn list_page(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<SamlServiceProvider>> {
        // Applied to BOTH queries, so `total` counts matches rather than rows.
        let search = search_filter(&pagination, &["display_name", "entity_id"]);
        let search_term = search_bind(&pagination);

        let mut count_result = self
            .db
            .current()
            .query(format!(
                "SELECT count() AS total FROM saml_service_provider \
                 WHERE tenant_id = $tenant_id{search} GROUP ALL"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("search", search_term.clone()))
            .await
            .map_err(DbError::from)?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;

        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {COLUMNS} FROM saml_service_provider \
                 WHERE tenant_id = $tenant_id{search} \
                 ORDER BY created_at ASC \
                 LIMIT $limit START $offset"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("search", search_term))
            .bind(("limit", pagination.limit))
            .bind(("offset", pagination.offset))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<SpRow> = result.take(0).map_err(DbError::from)?;
        let items = rows
            .into_iter()
            .map(|row| row.into_domain().map_err(AxiamError::from))
            .collect::<AxiamResult<Vec<_>>>()?;
        Ok(paginate(items, count_rows, &pagination))
    }

    async fn groups_outside_tenant(
        &self,
        tenant_id: Uuid,
        groups: &[Uuid],
    ) -> AxiamResult<Vec<Uuid>> {
        #[derive(Debug, SurrealValue)]
        struct GroupIdRow {
            record_id: String,
        }
        let mut wanted: Vec<Uuid> = Vec::new();
        for group in groups {
            if !wanted.contains(group) {
                wanted.push(*group);
            }
        }
        if wanted.is_empty() {
            return Ok(Vec::new());
        }
        let mut result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id FROM group \
                 WHERE tenant_id = $tenant_id AND meta::id(id) IN $ids",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind((
                "ids",
                wanted.iter().map(Uuid::to_string).collect::<Vec<_>>(),
            ))
            .await
            .map_err(DbError::from)?;
        let found: Vec<GroupIdRow> = result.take(0).map_err(DbError::from)?;
        let found: std::collections::HashSet<String> =
            found.into_iter().map(|row| row.record_id).collect();
        Ok(wanted
            .into_iter()
            .filter(|group| !found.contains(&group.to_string()))
            .collect())
    }

    async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: SamlServiceProviderInput,
    ) -> AxiamResult<SamlServiceProvider> {
        let values = bound(&input)?;
        // The tenant guard is in the `WHERE`, so a row of another tenant
        // matches nothing and reads back as `NotFound`.
        let result = self
            .db
            .current()
            .query(format!(
                "UPDATE type::record('saml_service_provider', $id) SET \
                 {SET_CLAUSE}, updated_at = time::now() \
                 WHERE tenant_id = $tenant_id"
            ))
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("enabled", input.enabled))
            .bind(("display_name", input.display_name))
            .bind(("entity_id", input.entity_id))
            .bind(("acs_urls_json", values.acs_urls_json))
            .bind(("slo_url", input.slo_url))
            .bind((
                "slo_binding",
                input.slo_binding.map(|b| b.as_str().to_owned()),
            ))
            .bind(("name_id_format", input.name_id_format.as_str().to_owned()))
            .bind(("sign_responses", input.sign_responses))
            .bind(("encrypt_assertions", input.encrypt_assertions))
            .bind(("sp_signing_cert_pem", input.sp_signing_cert_pem))
            .bind(("sp_encryption_cert_pem", input.sp_encryption_cert_pem))
            .bind((
                "want_authn_requests_signed",
                input.want_authn_requests_signed,
            ))
            .bind(("allow_idp_initiated", input.allow_idp_initiated))
            .bind(("attribute_mappings_json", values.attribute_mappings_json))
            .bind(("allowed_groups", values.allowed_groups))
            .await
            .map_err(DbError::from)?;
        result
            .check()
            .map_err(|e| classify_write_error(e, ENTITY))?;

        self.get(tenant_id, id).await
    }

    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        // One transaction: the existence guard first (a foreign or unknown id
        // aborts with `NotFound` before anything is removed), then what the
        // datastore holds for the SP, then the SP. A reader never sees the
        // registration gone with its records left, or the reverse.
        let guard = crate::helpers::delete_existence_guard("saml_service_provider");
        let query = format!(
            "BEGIN TRANSACTION; \
             {guard} \
             {SP_DELETE_CASCADE} \
             DELETE type::record('saml_service_provider', $id) WHERE tenant_id = $tenant_id; \
             COMMIT TRANSACTION"
        );
        let mut result = self
            .db
            .current()
            .query(query)
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        map_delete_errors(result.take_errors(), ENTITY, &id.to_string())?;
        Ok(())
    }
}

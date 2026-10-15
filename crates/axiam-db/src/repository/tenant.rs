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
use crate::helpers::{
    CountRow, classify_write_error, paginate, retry_hot_row, take_first_or_not_found,
};

/// D-55: bumped whenever this process creates or deletes a tenant or an
/// organization, **after** the write commits, so a tenant count cached at an
/// earlier generation is known to be stale at once (the SSF shared-issuer gate,
/// `axiam_oauth2::ssf::SsfIssuerGate`). Process-wide on purpose: every repository
/// handle of the process writes the same datastore.
static TENANT_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Record that the set of tenants or organizations changed (D-55).
pub(crate) fn bump_tenant_generation() {
    TENANT_GENERATION.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// The current tenant generation (D-55).
#[must_use]
pub fn tenant_generation() -> u64 {
    TENANT_GENERATION.load(std::sync::atomic::Ordering::SeqCst)
}

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

/// The tenant purge (#523, D-4): what the cleanup job's `tenant_purge` sweep
/// calls. See [`super::tenant_purge`] for the order and why it is that order.
impl<C: Connection> SurrealTenantRepository<C> {
    /// The tenants a deletion has tombstoned and the purge has not yet removed,
    /// oldest deletion first.
    ///
    /// # Errors
    ///
    /// A datastore failure.
    pub async fn list_tombstoned(&self) -> AxiamResult<Vec<Uuid>> {
        #[derive(Debug, SurrealValue)]
        struct IdRow {
            record_id: String,
        }
        let mut result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, deleted_at FROM tenant \
                 WHERE deleted_at != NONE ORDER BY deleted_at ASC",
            )
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(DbError::from)?;
        let rows: Vec<IdRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows
            .into_iter()
            .filter_map(|r| Uuid::parse_str(&r.record_id).ok())
            .collect())
    }

    /// Claim a tombstoned tenant's purge for this replica (#610): `true` when
    /// this call won it, `false` when the tenant is not tombstoned (live, or
    /// already purged) or another replica's claim, stamped after
    /// `now - lease`, still holds.
    ///
    /// The cleanup job runs on every replica, so every replica's
    /// `tenant_purge` sweep sees the same tombstoned tenant. The lease is the
    /// precondition of the write (the SCIM `claim_reconciliation` pattern):
    /// of two concurrent claimants, one write matches and stamps
    /// `purge_claimed_at`; the other either matches nothing or loses the
    /// optimistic write, retries, and then finds the winner's stamp. A claim
    /// older than the lease is taken over, so a replica that claimed and died
    /// holds the tenant back for one lease at most. A purge still running when
    /// its lease runs out may then overlap another replica's; every step of
    /// it is idempotent and only one of them removes the tenant row (see
    /// [`Self::purge_tombstoned`]), so that costs work, not correctness.
    ///
    /// # Errors
    ///
    /// A datastore failure.
    pub async fn claim_purge(
        &self,
        id: Uuid,
        now: DateTime<Utc>,
        lease: chrono::TimeDelta,
    ) -> AxiamResult<bool> {
        let cutoff = now - lease;
        retry_hot_row(|| async {
            let mut result = self
                .db
                .current()
                .query(
                    "UPDATE type::record('tenant', $id) SET purge_claimed_at = $now \
                     WHERE deleted_at != NONE \
                       AND (purge_claimed_at = NONE OR purge_claimed_at <= $cutoff) \
                     RETURN VALUE meta::id(id)",
                )
                .bind(("id", id.to_string()))
                .bind(("now", now))
                .bind(("cutoff", cutoff))
                .await
                .map_err(DbError::from)?
                .check()
                .map_err(|e| classify_write_error(e, "tenant"))?;
            let claimed: Vec<String> = result.take(0).map_err(DbError::from)?;
            Ok::<_, DbError>(!claimed.is_empty())
        })
        .await
        .map_err(Into::into)
    }

    /// Give up a claim [`Self::claim_purge`] stamped at `claimed_at`, so the
    /// next sweep — this replica's or another's — retries a purge that failed
    /// without waiting out the lease. A claim another replica has since taken
    /// over carries a different stamp and is left alone.
    ///
    /// # Errors
    ///
    /// A datastore failure.
    pub async fn release_purge_claim(
        &self,
        id: Uuid,
        claimed_at: DateTime<Utc>,
    ) -> AxiamResult<()> {
        retry_hot_row(|| async {
            self.db
                .current()
                .query(
                    "UPDATE type::record('tenant', $id) SET purge_claimed_at = NONE \
                     WHERE purge_claimed_at = $claimed_at",
                )
                .bind(("id", id.to_string()))
                .bind(("claimed_at", claimed_at))
                .await
                .map_err(DbError::from)?
                .check()
                .map_err(|e| classify_write_error(e, "tenant"))?;
            Ok::<_, DbError>(())
        })
        .await
        .map_err(Into::into)
    }

    /// Remove every tenant-scoped row of a **tombstoned** tenant, then the
    /// tenant row. Of its audit trail, only the rows the export its deletion
    /// required holds go — those at or before the export time the
    /// `tenants.deleted` record names (R1W1-04); the rest, or all of it when no
    /// export time can be read, stays for the retention sweep. The report says
    /// which.
    ///
    /// Each table is one idempotent `DELETE`; a failure stops the purge with
    /// the tenant still tombstoned, and calling this again resumes it. A live
    /// tenant is refused before anything is touched — the purge never decides
    /// on its own that a tenant is gone.
    ///
    /// `Ok` means **this call** removed the tenant row (#610): when two purges
    /// of one tenant overlap — a claim whose lease ran out mid-purge, taken
    /// over by another replica — both run the same idempotent steps, but only
    /// one of their final `DELETE`s finds the row, and the other answers
    /// `NotFound`, as for a tenant purged before the call. The caller records
    /// the purge on `Ok` only, so it is recorded once.
    ///
    /// # Errors
    ///
    /// `NotFound` for a tenant that is not tombstoned (live, or already
    /// purged — before this call or while it ran); a datastore failure
    /// otherwise.
    pub async fn purge_tombstoned(
        &self,
        id: Uuid,
    ) -> AxiamResult<super::tenant_purge::TenantPurgeReport> {
        let report = self.purge_tombstoned_rows(id).await?;
        self.remove_purged_tenant(id).await?;
        Ok(report)
    }

    /// The first part of [`Self::purge_tombstoned`]: every tenant-scoped row of
    /// a **tombstoned** tenant, not its tenant row (#655).
    ///
    /// The tenant stays tombstoned, so a purge stopped anywhere in here — a
    /// failure, or the cleanup task giving the purge up because the process is
    /// stopping — is resumed by the next call: every step is an idempotent
    /// `DELETE`. Nothing here is a point of no return.
    ///
    /// # Errors
    ///
    /// `NotFound` for a tenant that is not tombstoned (live, or already
    /// purged); a datastore failure otherwise.
    pub async fn purge_tombstoned_rows(
        &self,
        id: Uuid,
    ) -> AxiamResult<super::tenant_purge::TenantPurgeReport> {
        if !self.list_tombstoned().await?.contains(&id) {
            return Err(DbError::NotFound {
                entity: "tombstoned tenant".into(),
                id: id.to_string(),
            }
            .into());
        }
        Ok(super::tenant_purge::purge_rows(
            &self.db,
            id,
            super::tenant_purge::PurgeScope::Tombstoned,
        )
        .await?)
    }

    /// The last part of [`Self::purge_tombstoned`]: remove the tenant row, only
    /// while it is still tombstoned (#655). Call it only after
    /// [`Self::purge_tombstoned_rows`] has succeeded for the tenant; a tenant
    /// row removed before its rows leaves them for the orphan scan.
    ///
    /// This is the purge's **point of no return**: once the row is gone, no
    /// later sweep finds the tenant, so whoever removed it is the only one that
    /// can write `tenants.purged`. `Ok` means this call removed it.
    ///
    /// # Errors
    ///
    /// `NotFound` when the row is not there or not tombstoned — an overlapping
    /// purge removed it first (#610); a datastore failure otherwise.
    pub async fn remove_purged_tenant(&self, id: Uuid) -> AxiamResult<()> {
        // Only while still tombstoned: the guard is in the statement too, so
        // nothing here can remove a live tenant's row. `RETURN BEFORE` says
        // whether this call removed it, or an overlapping purge did.
        let mut result = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM (DELETE type::record('tenant', $id) \
                 WHERE deleted_at != NONE RETURN BEFORE) GROUP ALL",
            )
            .bind(("id", id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(DbError::from)?;
        let removed: Vec<CountRow> = result.take(0).map_err(DbError::from)?;
        if removed.first().is_none_or(|r| r.total == 0) {
            return Err(DbError::NotFound {
                entity: "tombstoned tenant".into(),
                id: id.to_string(),
            }
            .into());
        }
        Ok(())
    }

    /// Tenant ids that own rows but have no tenant row at all — the residue of
    /// deletions made before the tombstone existed (#523), which removed the
    /// tenant row and nothing else.
    ///
    /// Reads every tenant-scoped table but the audit trail (see
    /// [`super::tenant_purge::PurgeScope::Orphan`]), so the caller runs it
    /// rarely rather than on every sweep.
    ///
    /// # Errors
    ///
    /// A datastore failure.
    pub async fn orphaned_tenant_ids(&self) -> AxiamResult<Vec<Uuid>> {
        Ok(super::tenant_purge::orphaned_tenant_ids(&self.db).await?)
    }

    /// Remove an orphaned tenant id's rows, as [`Self::purge_tombstoned`] does
    /// for a tombstoned tenant, except its audit trail, which no export receipt
    /// covers and which the audit retention sweep governs (the report counts
    /// it as kept).
    ///
    /// # Errors
    ///
    /// `Conflict` when a tenant row with this id exists (live or tombstoned);
    /// a datastore failure otherwise.
    pub async fn purge_orphan(
        &self,
        id: Uuid,
    ) -> AxiamResult<super::tenant_purge::TenantPurgeReport> {
        let mut result = self
            .db
            .current()
            .query("SELECT count() AS total FROM type::record('tenant', $id) GROUP ALL")
            .bind(("id", id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(DbError::from)?;
        let rows: Vec<CountRow> = result.take(0).map_err(DbError::from)?;
        if rows.first().is_some_and(|r| r.total > 0) {
            return Err(axiam_core::error::AxiamError::Conflict {
                reason: "a tenant row exists for this id; it is not an orphan".into(),
            });
        }
        Ok(
            super::tenant_purge::purge_rows(&self.db, id, super::tenant_purge::PurgeScope::Orphan)
                .await?,
        )
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
        bump_tenant_generation();

        Ok(row.into_tenant(id)?)
    }

    async fn get_by_id(&self, id: Uuid) -> AxiamResult<Tenant> {
        let id_str = id.to_string();

        let mut result = self
            .db
            .current()
            .query("SELECT * FROM type::record('tenant', $id) WHERE deleted_at = NONE")
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
                 WHERE organization_id = $org_id AND slug = $slug \
                   AND deleted_at = NONE",
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
                 WHERE organization_id = $org_id AND kind = 'organization' \
                   AND deleted_at = NONE",
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

        // #523: a tombstoned tenant is not there to update — `NotFound`, as
        // every read answers.
        let query = format!(
            "UPDATE type::record('tenant', $id) SET {} WHERE deleted_at = NONE",
            sets.join(", ")
        );

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
        // #523 (P23W2-04, D-4): deleting a tenant TOMBSTONES it. The row keeps
        // its data and gains `deleted_at`, which takes it out of every read in
        // this file (and the settings repository's tenant lookup): sign-in,
        // token issuance, refresh and every handler that resolves the tenant
        // answer as for a tenant that does not exist, from this commit on. The
        // cleanup job's `tenant_purge` sweep then removes every tenant-scoped
        // row in the order user erasure uses (`tenant_purge`), and the tenant
        // row last. The slug stays claimed by the tombstone until then, so a
        // new tenant cannot take it while the old one's rows are still there.
        //
        // In the same transaction, and so in the request:
        //
        // * Its sessions are deleted and its refresh tokens revoked — the
        //   erasure's first step, so the tenant's last session cannot refresh
        //   and its access tokens fail the per-request session check. The
        //   handler revoked them once already, through the repositories that
        //   publish to the revocation feed and drop the validity cache; this
        //   pass catches a sign-in that raced it, atomically with the stamp.
        //
        // * The rows that make AXIAM act for the tenant, or hold its credentials
        //   for systems outside AXIAM, go now rather than at the purge, so no
        //   background job — the directory sync, the SCIM delivery and
        //   reconciliation, the SSF transmitter — works for a tenant that no
        //   longer exists: its directory configuration and sync state (T23.3.1,
        //   T23.3.5: an encrypted bind credential, account ids), its SAML
        //   service providers, IdP signing credential, pending `AuthnRequest`s
        //   and single-logout state (T23.2.1–T23.2.4: a sealed private key, the
        //   `NameID` each SP was given), its SSF streams, step-up records and
        //   buffered events (T23.5.2: a sealed receiver credential, subjects'
        //   addresses), its CIBA requests, and its SCIM targets with their links
        //   and delivery state.
        //
        // * R1W1-01: its certificates and signing CAs are revoked. The handler
        //   revoked them once already, through the services that forward a
        //   `vault_pki` leaf to Vault and release a CA's key; this pass catches
        //   one issued while it ran, atomically with the stamp. A deleted
        //   tenant's certificates are disowned, so they go on their issuers'
        //   revocation lists — and the purge keeps each revoked row until
        //   eight days after it expires, so they stay there (`tenant_purge`).
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
                 DELETE session WHERE tenant_id = $id; \
                 UPDATE oauth2_refresh_token SET revoked = true \
                     WHERE tenant_id = $id AND revoked = false; \
                 DELETE directory_config WHERE tenant_id = $id; \
                 DELETE directory_sync_state WHERE tenant_id = $id; \
                 DELETE saml_service_provider WHERE tenant_id = $id; \
                 DELETE saml_idp_credential WHERE tenant_id = $id; \
                 DELETE saml_authn_request WHERE tenant_id = $id; \
                 DELETE saml_sp_session WHERE tenant_id = $id; \
                 DELETE saml_logout_run WHERE tenant_id = $id; \
                 DELETE ssf_event_buffer WHERE tenant_id = $id; \
                 DELETE ssf_step_up WHERE tenant_id = $id; \
                 DELETE ciba_request WHERE tenant_id = $id; \
                 DELETE ssf_stream WHERE tenant_id = $id; \
                 DELETE scim_target_link WHERE tenant_id = $id; \
                 DELETE scim_target_state WHERE tenant_id = $id; \
                 DELETE scim_target WHERE tenant_id = $id; \
                 UPDATE certificate SET status = 'Revoked', \
                     revoked_at = revoked_at ?? time::now() \
                     WHERE tenant_id = $id AND status != 'Revoked' \
                       AND not_after > time::now(); \
                 UPDATE ca_certificate SET status = 'Revoked', \
                     revoked_at = revoked_at ?? time::now() \
                     WHERE tenant_id = $id AND status != 'Revoked' \
                       AND not_after > time::now(); \
                 UPDATE type::record('tenant', $id) \
                     SET deleted_at = time::now(), updated_at = time::now() \
                     WHERE deleted_at = NONE; \
                 COMMIT TRANSACTION;",
            )
            .bind(("id", id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(DbError::from)?;

        bump_tenant_generation();
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
                 WHERE organization_id = $org_id AND deleted_at = NONE GROUP ALL",
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
                 WHERE organization_id = $org_id AND deleted_at = NONE \
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

/// D-55: the deployment's tenant count for the SSF shared-issuer gate — the
/// standard tenants of every organization, or the organizations if there are
/// more of those (see [`axiam_core::models::ssf::DeploymentTenants`]).
impl<C: Connection> axiam_core::models::ssf::DeploymentTenants for SurrealTenantRepository<C> {
    fn count_for_shared_issuer(&self) -> axiam_core::models::ssf::SsfFuture<'_, AxiamResult<u64>> {
        Box::pin(async move {
            // An absent `kind` is a standard tenant (rows older than
            // organization scope), so the test is "not the organization's own".
            let mut result = self
                .db
                .current()
                .query(
                    "SELECT count() AS total FROM tenant \
                         WHERE (kind = NONE OR kind != 'organization') \
                           AND deleted_at = NONE GROUP ALL; \
                     SELECT count() AS total FROM organization GROUP ALL",
                )
                .await
                .map_err(DbError::from)?;
            let tenants: Vec<CountRow> = result.take(0).map_err(DbError::from)?;
            let organizations: Vec<CountRow> = result.take(1).map_err(DbError::from)?;
            let tenants = tenants.first().map_or(0, |r| r.total);
            let organizations = organizations.first().map_or(0, |r| r.total);
            Ok(tenants.max(organizations))
        })
    }

    fn generation(&self) -> u64 {
        tenant_generation()
    }
}

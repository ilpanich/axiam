//! The tenant purge (#523, P23W2-04, D-4).
//!
//! Deleting a tenant tombstones it ([`super::SurrealTenantRepository`]'s
//! `delete`): the row stays, with `deleted_at` set, so the tenant leaves every
//! read path at once while its data is still there. The cleanup job's
//! `tenant_purge` sweep then removes the data — every row of every
//! tenant-scoped table — and the tenant row last.
//!
//! # The order
//!
//! [`TENANT_PURGE_ORDER`] follows the order the GDPR user erasure uses
//! (`axiam_server::cleanup`'s purge pipeline, steps (a) to (f)), widened from
//! one account to every account and every configuration of the tenant:
//!
//! 1. [`PurgeStage::Grants`] — sessions, refresh tokens and every other grant or
//!    in-flight credential, so nothing issued to the tenant can be redeemed
//!    while the rest goes (erasure step (a)). The request that tombstoned the
//!    tenant already revoked its sessions and refresh tokens; this removes the
//!    rows.
//! 2. [`PurgeStage::IdentityLinks`] — federation links (step (b)).
//! 3. [`PurgeStage::Credentials`] — passkeys, OPAQUE records, password history
//!    (step (b2)).
//! 4. [`PurgeStage::Authorization`] — groups, roles, permissions, scopes,
//!    resources and service accounts; their graph edges go with the records
//!    (step (b3)).
//! 5. [`PurgeStage::AuditTrail`] — the tenant's own audit entries and their
//!    signatures (step (d)). The deletion was refused until the trail had been
//!    exported (T-118), so the purge destroys nothing the operator does not hold
//!    a copy of; the `tenant.deleted` record is written to the system log (the
//!    nil tenant) and is never touched here.
//! 6. [`PurgeStage::Records`] — consents, deletion requests, export jobs and
//!    erasure proofs (steps (f) and (g)).
//! 7. [`PurgeStage::Accounts`] — the user rows themselves (step (e); an erasure
//!    anonymizes one account in place, a tenant purge removes them all).
//! 8. [`PurgeStage::Configuration`] — everything the tenant configured,
//!    including the encrypted credentials it held for systems outside AXIAM.
//!
//! Every step is one idempotent `DELETE … WHERE <tenant>`, so a purge that
//! fails part-way stops there, leaves the tenant tombstoned, and is resumed by
//! the next sweep; the tenant row goes only after every step succeeded.
//!
//! # Revocation evidence outlives the tenant (R1W1-01)
//!
//! Two tables are not emptied: `certificate` and `ca_certificate` keep every
//! **revoked, unexpired** row ([`Retain::RevokedUntilExpiry`]). An issuing CA's
//! revocation list (`axiam_pki::crl`, T-102) is read from those rows, across
//! tenants, by issuer; deleting them took a revoked leaf off its organization
//! CA's list and made it valid again to every relying party outside AXIAM. The
//! deletion revoked every certificate and signing CA of the tenant already
//! (the handler, and again the tombstone transaction), and the step revokes
//! anything still unrevoked first, so after the purge each of the tenant's
//! unexpired certificates is a revoked row its issuer's list names — and that
//! every authentication path refuses, since each reads the row's status.
//!
//! What is kept is what the list needs and no more: the step clears a
//! certificate's free-form `metadata` and a CA's sealed private key. The rows
//! name a tenant id with no tenant row, which is what the orphan scan looks
//! for; it ignores a kept row until it expires, and then the orphan purge
//! removes it — the cleanup job deletes the evidence once no relying party can
//! need it.
//!
//! # Completeness is pinned
//!
//! `schema::tests::every_tenant_scoped_table_is_purged` scans every migration
//! for a table with a `tenant_id` field (or the `scope`/`scope_id` pair) and
//! fails when one is missing here — a table added later without a purge step
//! fails the build's tests rather than surviving its tenant.

use std::collections::BTreeSet;

use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;

/// How a table names the tenant a row belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantKey {
    /// `tenant_id = <tenant>` — every table with a `tenant_id` field.
    TenantId,
    /// `scope = 'tenant' AND scope_id = <tenant>` — the tables whose rows
    /// belong to an organization or to a tenant (`scope = 'org'` rows are never
    /// touched).
    Scope,
}

/// Which part of the user-erasure order a step belongs to (see the module
/// documentation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeStage {
    /// Sessions, refresh tokens and every other grant or pending credential.
    Grants,
    /// Federation links.
    IdentityLinks,
    /// Stored credential material.
    Credentials,
    /// The authorization graph's records.
    Authorization,
    /// The tenant's own audit entries and their signatures.
    AuditTrail,
    /// GDPR records: consents, deletion requests, export jobs, erasure proofs.
    Records,
    /// The user rows.
    Accounts,
    /// The tenant's configuration and the credentials it holds for others.
    Configuration,
}

/// Which of a table's rows the purge keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retain {
    /// None: every row of the tenant goes.
    Nothing,
    /// A revoked certificate whose `not_after` is still ahead — the evidence
    /// its issuer's revocation list is read from (R1W1-01; see the module
    /// documentation). Every other row goes; an unrevoked, unexpired row is
    /// revoked first, and a kept row has `strip` applied (an `UPDATE … SET`
    /// clause clearing what the list does not need).
    RevokedUntilExpiry {
        /// The `SET` clause applied to a kept row.
        strip: &'static str,
    },
}

/// The condition a row the purge keeps satisfies.
const KEPT_REVOCATION: &str = "status = 'Revoked' AND not_after > time::now()";

/// One table of the purge.
#[derive(Debug, Clone, Copy)]
pub struct PurgeStep {
    /// The table.
    pub table: &'static str,
    /// How its rows name their tenant.
    pub key: TenantKey,
    /// Where in the erasure order it is purged.
    pub stage: PurgeStage,
    /// Which rows outlive the purge.
    pub retain: Retain,
}

impl PurgeStep {
    const fn by_tenant(table: &'static str, stage: PurgeStage) -> Self {
        Self {
            table,
            key: TenantKey::TenantId,
            stage,
            retain: Retain::Nothing,
        }
    }

    const fn by_scope(table: &'static str, stage: PurgeStage) -> Self {
        Self {
            table,
            key: TenantKey::Scope,
            stage,
            retain: Retain::Nothing,
        }
    }

    /// A certificate table: keyed by `tenant_id`, keeping revocation evidence
    /// until it expires.
    const fn keeping_revocations(
        table: &'static str,
        strip: &'static str,
        stage: PurgeStage,
    ) -> Self {
        Self {
            table,
            key: TenantKey::TenantId,
            stage,
            retain: Retain::RevokedUntilExpiry { strip },
        }
    }

    /// The statement that removes the tenant's rows (`$id` is the tenant).
    ///
    /// The table name and a retaining step's `strip` clause are compile-time
    /// constants of [`TENANT_PURGE_ORDER`], never input, so formatting them
    /// into the statement is safe.
    fn delete_statement(&self) -> String {
        let table = self.table;
        match (self.key, self.retain) {
            (TenantKey::TenantId, Retain::Nothing) => {
                format!("DELETE {table} WHERE tenant_id = $id")
            }
            (TenantKey::TenantId, Retain::RevokedUntilExpiry { strip }) => format!(
                "UPDATE {table} SET status = 'Revoked', revoked_at = revoked_at ?? time::now() \
                     WHERE tenant_id = $id AND status != 'Revoked' AND not_after > time::now(); \
                 UPDATE {table} SET {strip} WHERE tenant_id = $id AND {KEPT_REVOCATION}; \
                 DELETE {table} WHERE tenant_id = $id AND NOT ({KEPT_REVOCATION});"
            ),
            (TenantKey::Scope, _) => {
                format!("DELETE {table} WHERE scope = 'tenant' AND scope_id = $id")
            }
        }
    }

    /// The condition, beyond the tenant, a row must meet to be purged — what
    /// the orphan scan counts.
    fn purgeable(&self) -> String {
        match self.retain {
            Retain::Nothing => "true".into(),
            Retain::RevokedUntilExpiry { .. } => format!("NOT ({KEPT_REVOCATION})"),
        }
    }
}

use PurgeStage::{
    Accounts, AuditTrail, Authorization, Configuration, Credentials, Grants, IdentityLinks, Records,
};

/// Every tenant-scoped table, in the order a tenant purge removes it.
pub const TENANT_PURGE_ORDER: &[PurgeStep] = &[
    // (a) Grants and in-flight credentials — sessions and refresh tokens first.
    PurgeStep::by_tenant("session", Grants),
    PurgeStep::by_tenant("oauth2_refresh_token", Grants),
    PurgeStep::by_tenant("session_client", Grants),
    PurgeStep::by_tenant("oauth2_auth_code", Grants),
    PurgeStep::by_tenant("pushed_auth_request", Grants),
    PurgeStep::by_tenant("device_grant", Grants),
    PurgeStep::by_tenant("ciba_request", Grants),
    PurgeStep::by_tenant("permission_ticket", Grants),
    PurgeStep::by_tenant("oauth2_registration_token", Grants),
    PurgeStep::by_tenant("scim_token", Grants),
    PurgeStep::by_tenant("sso_handoff_code", Grants),
    PurgeStep::by_tenant("federation_login_state", Grants),
    PurgeStep::by_tenant("password_reset_token", Grants),
    PurgeStep::by_tenant("email_verification_token", Grants),
    PurgeStep::by_tenant("saml_authn_request", Grants),
    PurgeStep::by_tenant("saml_sp_session", Grants),
    PurgeStep::by_tenant("saml_logout_run", Grants),
    PurgeStep::by_tenant("ssf_step_up", Grants),
    PurgeStep::by_tenant("ssf_event_buffer", Grants),
    PurgeStep::by_tenant("oauth2_proof_replay", Grants),
    PurgeStep::by_tenant("saml_assertion_replay", Grants),
    PurgeStep::by_tenant("amqp_nonce_replay", Grants),
    // (b) Identity links.
    PurgeStep::by_tenant("federation_link", IdentityLinks),
    // (b2) Stored credential material.
    PurgeStep::by_tenant("webauthn_credential", Credentials),
    PurgeStep::by_tenant("opaque_credential", Credentials),
    PurgeStep::by_tenant("password_history", Credentials),
    // (b3) The authorization graph: groups (and their `member_of` edges)
    // before roles (and their `has_role` / `grants` edges), as the erasure
    // removes memberships before role assignments.
    PurgeStep::by_tenant("group", Authorization),
    PurgeStep::by_tenant("role", Authorization),
    PurgeStep::by_tenant("permission", Authorization),
    PurgeStep::by_tenant("scope", Authorization),
    PurgeStep::by_tenant("resource", Authorization),
    PurgeStep::by_tenant("service_account", Authorization),
    // (d) The tenant's own audit trail, exported before the deletion (T-118).
    PurgeStep::by_tenant("audit_log", AuditTrail),
    PurgeStep::by_tenant("audit_signature", AuditTrail),
    // (f)/(g) GDPR records.
    PurgeStep::by_tenant("consent", Records),
    PurgeStep::by_tenant("account_deletion", Records),
    PurgeStep::by_tenant("export_job", Records),
    PurgeStep::by_tenant("erasure_proof", Records),
    // (e) The accounts.
    PurgeStep::by_tenant("user", Accounts),
    // Configuration, and the credentials the tenant held for others.
    PurgeStep::by_tenant("federation_config", Configuration),
    PurgeStep::by_scope("email_config", Configuration),
    PurgeStep::by_scope("email_template", Configuration),
    PurgeStep::by_scope("security_settings", Configuration),
    PurgeStep::by_tenant("webhook", Configuration),
    // A rule's notification windows (#551, schema v85) before the rule.
    PurgeStep::by_tenant("notification_window", Configuration),
    PurgeStep::by_tenant("notification_rule", Configuration),
    PurgeStep::by_tenant("reactor", Configuration),
    PurgeStep::by_tenant("oauth2_client", Configuration),
    // R1W1-01: revocation evidence stays until it expires; see the module
    // documentation.
    PurgeStep::keeping_revocations("certificate", "metadata = {}", Configuration),
    PurgeStep::keeping_revocations(
        "ca_certificate",
        "encrypted_private_key = NONE",
        Configuration,
    ),
    PurgeStep::by_tenant("pgp_key", Configuration),
    PurgeStep::by_tenant("webauthn_attestation_policy", Configuration),
    PurgeStep::by_tenant("opaque_server_setup", Configuration),
    PurgeStep::by_tenant("saml_idp_credential", Configuration),
    PurgeStep::by_tenant("saml_service_provider", Configuration),
    PurgeStep::by_tenant("directory_sync_state", Configuration),
    PurgeStep::by_tenant("directory_config", Configuration),
    PurgeStep::by_tenant("scim_target_link", Configuration),
    PurgeStep::by_tenant("scim_target_state", Configuration),
    PurgeStep::by_tenant("scim_target", Configuration),
    PurgeStep::by_tenant("ssf_stream", Configuration),
    PurgeStep::by_tenant("seeder_state", Configuration),
    PurgeStep::by_tenant("organization_scope", Configuration),
];

/// Whose rows a purge removes, and whether it may take the audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PurgeScope {
    /// A tombstoned tenant: everything, its audit trail included (it was
    /// exported before the deletion was allowed, T-118).
    Tombstoned,
    /// A tenant id that has rows but no tenant row — left by a deletion made
    /// before the tombstone existed. Everything **but** the audit trail: no
    /// export receipt can be checked for it, and an audit entry naming a tenant
    /// id that never existed (a refused request) is a record the retention
    /// sweep, not this one, decides about.
    Orphan,
}

/// Remove `tenant_id`'s rows from every table of [`TENANT_PURGE_ORDER`], in
/// order, stopping at the first failure (every step is idempotent, so the next
/// sweep resumes).
pub(crate) async fn purge_rows<C: Connection>(
    db: &DbHandle<C>,
    tenant_id: Uuid,
    scope: PurgeScope,
) -> Result<(), DbError> {
    let id = tenant_id.to_string();
    for step in TENANT_PURGE_ORDER {
        if scope == PurgeScope::Orphan && step.stage == AuditTrail {
            continue;
        }
        db.current()
            .query(step.delete_statement())
            .bind(("id", id.clone()))
            .await?
            .check()
            .map_err(|e| DbError::Migration(format!("purging {}: {e}", step.table)))?;
    }
    Ok(())
}

/// Tenant ids that own rows in a tenant-scoped table (the audit trail aside,
/// see [`PurgeScope::Orphan`]) but have no tenant row — tombstoned or live.
///
/// A row a purge keeps ([`Retain::RevokedUntilExpiry`]) is not counted until
/// it expires; then it is, and the orphan purge removes it.
///
/// The tables are read **before** the tenant set: a tenant row is written
/// before any row naming it, so a tenant created while this runs is either
/// absent from the tables read or present in the set read after them, and is
/// never mistaken for an orphan. The nil id is the system log's and never an
/// orphan.
pub(crate) async fn orphaned_tenant_ids<C: Connection>(
    db: &DbHandle<C>,
) -> Result<Vec<Uuid>, DbError> {
    #[derive(Debug, SurrealValue)]
    struct ByTenant {
        #[surreal(default)]
        tenant_id: Option<String>,
    }
    #[derive(Debug, SurrealValue)]
    struct ByScope {
        #[surreal(default)]
        scope_id: Option<String>,
    }
    #[derive(Debug, SurrealValue)]
    struct TenantRow {
        record_id: String,
    }

    let mut named: BTreeSet<String> = BTreeSet::new();
    for step in TENANT_PURGE_ORDER {
        if step.stage == AuditTrail {
            continue;
        }
        // `GROUP BY` so the datastore returns one row per tenant, not one
        // per row of the table.
        match step.key {
            TenantKey::TenantId => {
                let mut result = db
                    .current()
                    .query(format!(
                        "SELECT tenant_id FROM {} WHERE {} GROUP BY tenant_id",
                        step.table,
                        step.purgeable()
                    ))
                    .await?
                    .check()?;
                let rows: Vec<ByTenant> = result.take(0)?;
                named.extend(rows.into_iter().filter_map(|r| r.tenant_id));
            }
            TenantKey::Scope => {
                let mut result = db
                    .current()
                    .query(format!(
                        "SELECT scope_id FROM {} WHERE scope = 'tenant' GROUP BY scope_id",
                        step.table
                    ))
                    .await?
                    .check()?;
                let rows: Vec<ByScope> = result.take(0)?;
                named.extend(rows.into_iter().filter_map(|r| r.scope_id));
            }
        }
    }

    let mut result = db
        .current()
        .query("SELECT meta::id(id) AS record_id FROM tenant")
        .await?
        .check()?;
    let tenants: Vec<TenantRow> = result.take(0)?;
    let known: BTreeSet<String> = tenants.into_iter().map(|t| t.record_id).collect();

    Ok(named
        .difference(&known)
        .filter_map(|id| Uuid::parse_str(id).ok())
        .filter(|id| !id.is_nil())
        .collect())
}

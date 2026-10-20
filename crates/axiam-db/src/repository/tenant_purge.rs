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
//! 5. [`PurgeStage::AuditTrail`] — the tenant's own audit entries **the
//!    export covered**, and the signatures over nothing but those entries (step
//!    (d); see "The audit trail" below). The `tenant.deleted` record is written
//!    to the system log (the nil tenant) and is never touched here.
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
//! # The audit trail: only what the export holds (R1W1-04, #602, D-5)
//!
//! The deletion is refused until the tenant's audit trail has been exported
//! (T-118), and the receipt it accepts may be up to six hours old. The export
//! covers the rows written up to the moment it started — its receipt's
//! `exported_through`, which the deletion copies into its `tenants.deleted`
//! system-log record as `audit_exported_through` — and nothing written after
//! it: the receipt itself, what the tenant did in the hours before the
//! deletion, and what the deletion and the time until the purge produced (its
//! revocations, refused sign-ins, refused client calls).
//!
//! So the purge deletes the tenant's `audit_log` rows with `timestamp` **at or
//! before** that export time and no others: the operator holds a copy of every
//! row it destroys. A later row stays under the tenant id, which no tenant row
//! names any more, as the rows of an orphaned tenant id do
//! ([`PurgeScope::Orphan`]); the audit retention sweep (T-119) deletes it once
//! it is older than the deployment's retention window, as it does every audit
//! row, whatever tenant it names. Nothing is copied to the system log. An
//! `audit_signature` row goes when **none** of its `entry_ids` is still in the
//! log — every entry it signs went with the purge; one that also signs a kept
//! entry stays, and the retention sweep removes it by its `signed_at`.
//!
//! The export time is read from the newest `tenants.deleted` record naming the
//! tenant (`resource_id`). A record written before this rule existed carries
//! only the receipt id, and the time is then read from that receipt's own
//! `exported_through`, which every receipt has carried. Either way it is
//! **clamped to the receipt's own `timestamp`** (R101W3-03, #637): the receipt
//! is written after the export drains, so an honest export time is earlier than
//! the receipt, and the row's `timestamp` is the datastore's while
//! `exported_through` is whatever its writer said. A receipt claiming to cover
//! rows after itself bounds the purge at itself, never later (the deletion
//! refuses such a receipt since #637, and no AMQP producer can write one —
//! `tenants.*` is reserved, [`axiam_core::models::audit::RESERVED_ACTION_NAMESPACES`]).
//! An honest receipt is after the bound, so the purge never deletes it. When no
//! time can be read — no deletion record (its write was dead-lettered, or the
//! purge ran before it landed), a record without one, or a record whose
//! receipt is not in the tenant's log — the purge deletes **no** audit row
//! and no signature of the tenant: it keeps everything, as for an orphan, and
//! leaves it to the retention sweep. `tenants.purged` records the export time
//! used (or `null`) and how many audit rows were deleted and kept
//! ([`TenantPurgeReport`]).
//!
//! The audit log is append-only (`super::audit`): the purge's audit stage is a
//! documented exception, and it deletes only what an export holds or what
//! signs nothing still in the log; it updates no audit row.
//!
//! # Revocation evidence outlives the tenant (R1W1-01)
//!
//! Two tables are not emptied: `certificate` and `ca_certificate` keep every
//! **revoked** row that is unexpired or expired less than eight days ago
//! ([`Retain::RevokedUntilExpiry`]; the grace is the longest time a list keeps
//! an expired entry, #608). An issuing CA's
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
//! for; it ignores a kept row until eight days after it expires, and then the
//! orphan purge removes it — the cleanup job deletes the evidence once no list
//! names it and no relying party can need it.
//!
//! # Completeness is pinned
//!
//! `schema::tests::every_tenant_scoped_table_is_purged` scans every migration
//! for a table with a `tenant_id` field (or the `scope`/`scope_id` pair) and
//! fails when one is missing here — a table added later without a purge step
//! fails the build's tests rather than surviving its tenant.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::CountRow;

/// The action of the **system**-log record a tenant deletion writes
/// (`resource_id` = the tenant). The purge reads the export time from it.
pub const TENANT_DELETED_ACTION: &str = "tenants.deleted";

/// The action of the export receipt in the tenant's own audit log (T-118).
pub const AUDIT_EXPORT_ACTION: &str = "tenants.audit_exported";

/// The action of the **system**-log record the cleanup job writes once it has
/// purged a deleted tenant (`resource_id` = the tenant).
pub const TENANT_PURGED_ACTION: &str = "tenants.purged";

/// Every control record the tenant deletion and purge write and read back.
///
/// Each falls in a namespace of
/// [`axiam_core::models::audit::RESERVED_ACTION_NAMESPACES`], so no AMQP
/// producer can write one (R101W3-03, #637); the purge's tests and the AMQP
/// consumer's pin that.
pub const TENANT_CONTROL_ACTIONS: &[&str] = &[
    TENANT_DELETED_ACTION,
    AUDIT_EXPORT_ACTION,
    TENANT_PURGED_ACTION,
];

/// The key of [`TENANT_DELETED_ACTION`]'s metadata holding the time the
/// accepted export covered up to (its receipt's [`RECEIPT_EXPORTED_THROUGH`]).
pub const DELETION_EXPORTED_THROUGH: &str = "audit_exported_through";

/// The key of [`TENANT_DELETED_ACTION`]'s metadata naming the receipt.
pub const DELETION_RECEIPT_ID: &str = "audit_export_receipt_id";

/// The key of an export receipt's metadata holding the instant the export
/// started: it holds every row with a `timestamp` at or before it.
pub const RECEIPT_EXPORTED_THROUGH: &str = "exported_through";

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
    /// A revoked certificate whose `not_after` is still ahead, or passed less
    /// than eight days ago — the evidence its issuer's revocation list is read
    /// from (R1W1-01, #608; see the module documentation). Every other row goes; an unrevoked, unexpired row is
    /// revoked first, and a kept row has `strip` applied (an `UPDATE … SET`
    /// clause clearing what the list does not need).
    RevokedUntilExpiry {
        /// The `SET` clause applied to a kept row.
        strip: &'static str,
    },
    /// `audit_log`: a row written after the export the deletion required
    /// (R1W1-04; see the module documentation). Rows with a `timestamp` at or
    /// before the export time go; the purge skips the step, keeping every row,
    /// when it knows no export time.
    AfterExport,
    /// `audit_signature`: a signature over at least one entry still in
    /// `audit_log` once [`Retain::AfterExport`] has run. A signature whose every
    /// entry is gone goes.
    CoveringKeptEntries,
}

/// How many days after its `notAfter` a revoked certificate's row is kept: the
/// longest an issuer's list can keep an expired entry (one `nextUpdate`
/// interval, at most seven days, #608) and a day's margin for the datastore's
/// clock. One spelling, a macro, because it feeds [`REVOCATION_GRACE_SECS`] and
/// the two `concat!`ed SurrealQL conditions [`KEPT_REVOCATION`] and
/// [`PAST_REVOCATION_GRACE`], so the number and the queries cannot drift apart.
/// The `axiam-server` test `kept_revocation_covers_the_longest_crl_interval`
/// ties it to `axiam_pki::crl::MAX_CRL_NEXT_UPDATE_SECS` (#621).
macro_rules! revocation_grace_days {
    () => {
        8
    };
}

/// [`KEPT_REVOCATION`]'s grace in seconds: eight days past `notAfter`.
///
/// Public so a test in a crate that sees both this one and `axiam-pki` can
/// check it against the longest list interval instead of repeating the number
/// (#621).
pub const REVOCATION_GRACE_SECS: u64 = revocation_grace_days!() * 86_400;

/// The condition a row the purge keeps satisfies: revoked, and expired for
/// less than eight days ([`REVOCATION_GRACE_SECS`]).
///
/// Not "unexpired" (#608). An issuing CA's list keeps an expired entry until it
/// has appeared on a list issued after the expiry — RFC 5280 §3.3 requires
/// that — which is up to one `nextUpdate` interval past `notAfter`, at most
/// seven days (`axiam_pki::crl::MAX_CRL_NEXT_UPDATE_SECS`). A row the purge
/// deleted inside that window would leave the list mid-way through a refresh
/// epoch, which changes the list without moving its `thisUpdate` and so breaks
/// the CRL number every replica derives from them. The eighth day is margin
/// for the datastore's clock against the replicas'.
///
/// Public, with [`PAST_REVOCATION_GRACE`], for the same test (#621); the text
/// is SurrealQL for this crate's own queries, not an API.
pub const KEPT_REVOCATION: &str = concat!(
    "status = 'Revoked' AND not_after > time::now() - ",
    revocation_grace_days!(),
    "d"
);

/// A certificate row no revocation list names any more and no relying party
/// can need: `notAfter` passed more than [`KEPT_REVOCATION`]'s grace ago,
/// whatever its status (W1.4, #618). What the cleanup job's certificate
/// retention sweep deletes in a live tenant — and what the tenant purge's
/// orphan scan has always waited for, now for every certificate rather than
/// only for the kept ones of a deleted tenant. The grace is spelled once, in
/// `revocation_grace_days!`, so the two cannot drift apart.
pub const PAST_REVOCATION_GRACE: &str =
    concat!("not_after <= time::now() - ", revocation_grace_days!(), "d");

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

    /// An audit table: keyed by `tenant_id`, keeping what no export holds.
    const fn audit(table: &'static str, retain: Retain) -> Self {
        Self {
            table,
            key: TenantKey::TenantId,
            stage: AuditTrail,
            retain,
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
    /// until eight days after it expires.
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
            (TenantKey::TenantId, Retain::AfterExport) => {
                format!("DELETE {table} WHERE tenant_id = $id AND timestamp <= $exported_through")
            }
            (TenantKey::TenantId, Retain::CoveringKeptEntries) => format!(
                "LET $kept = (SELECT VALUE meta::id(id) FROM audit_log WHERE tenant_id = $id); \
                 DELETE {table} WHERE tenant_id = $id \
                     AND array::len(array::intersect(entry_ids, $kept)) = 0;"
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
            // The audit trail is never read by the orphan scan (see
            // `orphaned_tenant_ids`); the retention sweep governs what is kept.
            Retain::AfterExport | Retain::CoveringKeptEntries => "false".into(),
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
    // (d) The tenant's own audit trail, as far as the export the deletion
    // required holds it (T-118, R1W1-04); see the module documentation.
    PurgeStep::audit("audit_log", Retain::AfterExport),
    PurgeStep::audit("audit_signature", Retain::CoveringKeptEntries),
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
    // R1W1-01, #608: revocation evidence stays until eight days after it
    // expires; see the module documentation.
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
    // W6.1 (schema v100): a segment's profile before the segment. The segment's
    // `resource` node goes with the `resource` step above.
    PurgeStep::by_tenant("reply_profile", Configuration),
    PurgeStep::by_tenant("network_segment", Configuration),
    PurgeStep::by_tenant("network_policy", Configuration),
    PurgeStep::by_tenant("ssf_stream", Configuration),
    PurgeStep::by_tenant("seeder_state", Configuration),
    PurgeStep::by_tenant("organization_scope", Configuration),
];

/// Whose rows a purge removes, and whether it may take the audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PurgeScope {
    /// A tombstoned tenant: everything, and of its audit trail the rows the
    /// export the deletion required holds (T-118, R1W1-04) — the rows at or
    /// before the export time its `tenants.deleted` record names. Later rows,
    /// or every row when no export time can be read, stay for the retention
    /// sweep.
    Tombstoned,
    /// A tenant id that has rows but no tenant row — left by a deletion made
    /// before the tombstone existed. Everything **but** the audit trail: no
    /// export receipt can be checked for it, and an audit entry naming a tenant
    /// id that never existed (a refused request) is a record the retention
    /// sweep, not this one, decides about.
    Orphan,
}

/// What a tenant purge did with the tenant's audit trail — what the cleanup
/// job records in `tenants.purged` (R1W1-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TenantPurgeReport {
    /// The time the export the deletion required covered up to, clamped to
    /// its receipt's own `timestamp` (R101W3-03); the purge deleted the
    /// tenant's audit rows at or before it. `None` when no export time could
    /// be read (an orphan, a deletion record without one, or one whose receipt
    /// is not in the tenant's log): no audit row was deleted.
    pub audit_exported_through: Option<DateTime<Utc>>,
    /// Audit rows of the tenant this purge deleted. A purge resumed after a
    /// failure counts only what the resuming pass deleted.
    pub audit_rows_deleted: u64,
    /// Audit rows of the tenant left for the retention sweep (T-119): those
    /// written after the export, or all of them when there is no export time.
    pub audit_rows_kept: u64,
    /// The id had no tenant row of its own: an orphaned tenant id
    /// ([`PurgeScope::Orphan`]), purged under the marker row its claim wrote
    /// (R101W1-09 (a)) — by the replica that claimed it, or, after that
    /// replica died, by the tombstoned-tenant purge that took the marker over.
    pub orphan: bool,
}

/// Remove `tenant_id`'s rows from every table of [`TENANT_PURGE_ORDER`], in
/// order, stopping at the first failure (every step is idempotent, so the next
/// sweep resumes).
pub(crate) async fn purge_rows<C: Connection>(
    db: &DbHandle<C>,
    tenant_id: Uuid,
    scope: PurgeScope,
) -> Result<TenantPurgeReport, DbError> {
    let id = tenant_id.to_string();
    let exported_through = match scope {
        PurgeScope::Tombstoned => audit_export_cutoff(db, tenant_id).await?,
        PurgeScope::Orphan => None,
    };
    let mut report = TenantPurgeReport {
        audit_exported_through: exported_through,
        orphan: scope == PurgeScope::Orphan,
        ..TenantPurgeReport::default()
    };
    for step in TENANT_PURGE_ORDER {
        let conn = db.current();
        let mut query = conn.query(step.delete_statement());
        if step.stage == AuditTrail {
            // No export time, no audit deletion: the trail stays whole for the
            // retention sweep, as an orphan's does.
            let Some(cutoff) = exported_through else {
                continue;
            };
            if step.retain == Retain::AfterExport {
                report.audit_rows_deleted = count(
                    db,
                    &format!(
                        "SELECT count() AS total FROM {} WHERE tenant_id = $id \
                         AND timestamp <= $exported_through GROUP ALL",
                        step.table
                    ),
                    &id,
                    Some(cutoff),
                )
                .await?;
            }
            query = query.bind(("exported_through", cutoff));
        }
        query
            .bind(("id", id.clone()))
            .await?
            .check()
            .map_err(|e| DbError::Migration(format!("purging {}: {e}", step.table)))?;
    }
    report.audit_rows_kept = count(
        db,
        "SELECT count() AS total FROM audit_log WHERE tenant_id = $id GROUP ALL",
        &id,
        None,
    )
    .await?;
    Ok(report)
}

/// One `count()` over `statement`, with `$id` (and `$exported_through`).
async fn count<C: Connection>(
    db: &DbHandle<C>,
    statement: &str,
    id: &str,
    exported_through: Option<DateTime<Utc>>,
) -> Result<u64, DbError> {
    let conn = db.current();
    let mut query = conn.query(statement).bind(("id", id.to_owned()));
    if let Some(cutoff) = exported_through {
        query = query.bind(("exported_through", cutoff));
    }
    let mut result = query.await?.check()?;
    let rows: Vec<CountRow> = result.take(0)?;
    Ok(rows.first().map_or(0, |r| r.total))
}

/// The time the export a tombstoned tenant's deletion accepted covered up to,
/// or `None` when it cannot be read (see the module documentation).
///
/// Read from the newest [`TENANT_DELETED_ACTION`] record in the system log
/// naming the tenant: its [`DELETION_EXPORTED_THROUGH`], or, for a record
/// written before that key existed, the [`RECEIPT_EXPORTED_THROUGH`] of the
/// receipt it names ([`DELETION_RECEIPT_ID`]).
///
/// **Clamped to the receipt's own `timestamp`** (R101W3-03, #637). The receipt
/// is written after the export drains, so an honest `exported_through` is
/// earlier than the row that carries it; the row's `timestamp` is assigned by
/// the datastore, while `exported_through` is metadata whoever wrote the row
/// chose. The bound is therefore `min(exported_through, receipt.timestamp)`:
/// a receipt claiming to cover rows written after it bounds the purge at the
/// receipt, never later. The receipt is looked up in **this tenant's** log, by
/// id and action. A record that names no receipt, or one that is not there —
/// a purge resumed after a clamped pass deleted it, or a record no deletion
/// wrote — leaves nothing to clamp to, and counts as no time: the purge then
/// keeps the whole trail. A value that is not an RFC 3339 time counts as
/// absent too.
async fn audit_export_cutoff<C: Connection>(
    db: &DbHandle<C>,
    tenant_id: Uuid,
) -> Result<Option<DateTime<Utc>>, DbError> {
    #[derive(Debug, SurrealValue)]
    struct MetadataRow {
        #[surreal(default)]
        metadata: Option<serde_json::Value>,
    }
    #[derive(Debug, SurrealValue)]
    struct ReceiptRow {
        #[surreal(default)]
        metadata: Option<serde_json::Value>,
        timestamp: DateTime<Utc>,
    }
    fn time_at(metadata: Option<&serde_json::Value>, key: &str) -> Option<DateTime<Utc>> {
        let raw = metadata?.get(key)?.as_str()?;
        DateTime::parse_from_rfc3339(raw)
            .ok()
            .map(|t| t.with_timezone(&Utc))
    }

    let mut result = db
        .current()
        .query(
            "SELECT metadata, timestamp FROM audit_log \
             WHERE tenant_id = $system AND action = $action AND resource_id = $id \
             ORDER BY timestamp DESC LIMIT 1",
        )
        .bind(("system", Uuid::nil().to_string()))
        .bind(("action", TENANT_DELETED_ACTION.to_owned()))
        .bind(("id", tenant_id.to_string()))
        .await?
        .check()?;
    let rows: Vec<MetadataRow> = result.take(0)?;
    let Some(deletion) = rows.into_iter().next().and_then(|r| r.metadata) else {
        return Ok(None);
    };
    // The receipt the deletion accepted, in the tenant's own log: the clamp's
    // source, and the export time of a record that does not carry one.
    let Some(receipt_id) = deletion.get(DELETION_RECEIPT_ID).and_then(|v| v.as_str()) else {
        return Ok(None);
    };
    let mut result = db
        .current()
        .query(
            "SELECT metadata, timestamp FROM type::record('audit_log', $receipt) \
             WHERE tenant_id = $id AND action = $action",
        )
        .bind(("receipt", receipt_id.to_owned()))
        .bind(("id", tenant_id.to_string()))
        .bind(("action", AUDIT_EXPORT_ACTION.to_owned()))
        .await?
        .check()?;
    let rows: Vec<ReceiptRow> = result.take(0)?;
    let Some(receipt) = rows.into_iter().next() else {
        return Ok(None);
    };
    let claimed = time_at(Some(&deletion), DELETION_EXPORTED_THROUGH)
        .or_else(|| time_at(receipt.metadata.as_ref(), RECEIPT_EXPORTED_THROUGH));
    Ok(claimed.map(|through| through.min(receipt.timestamp)))
}

/// A SurrealQL condition, on `$id`, true while that tenant id still owns a row
/// the orphan scan counts — a row of a tenant-scoped table but the audit trail,
/// other than revocation evidence the purge keeps ([`PurgeStep::purgeable`]).
///
/// The orphan claim's `CREATE` is conditional on it, in the same statement
/// ([`super::tenant::SurrealTenantRepository::claim_orphan_purge`], #714), so
/// that a marker only ever stands for a purge that had something to remove
/// (R101W1-09 (a)): a replica whose scan predates another replica's purge of
/// the same id finds nothing here and writes no marker. One `LIMIT 1` read
/// per table, all of them in the claim's statement.
pub(crate) fn purgeable_rows_condition() -> String {
    // One flat array of reads, not a chain of `OR`s: the chain nests one
    // expression per table, deep enough to overflow the datastore's evaluator
    // on a small stack.
    let reads = TENANT_PURGE_ORDER
        .iter()
        .filter(|step| step.stage != AuditTrail)
        .map(|step| match step.key {
            TenantKey::TenantId => format!(
                "(SELECT VALUE true FROM {} WHERE tenant_id = $id AND ({}) LIMIT 1)",
                step.table,
                step.purgeable()
            ),
            TenantKey::Scope => format!(
                "(SELECT VALUE true FROM {} \
                 WHERE scope = 'tenant' AND scope_id = $id LIMIT 1)",
                step.table
            ),
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("array::len(array::flatten([{reads}])) > 0")
}

/// Tenant ids that own rows in a tenant-scoped table (the audit trail aside,
/// see [`PurgeScope::Orphan`]) but have no tenant row — tombstoned or live.
///
/// A row a purge keeps ([`Retain::RevokedUntilExpiry`]) is not counted until
/// eight days after it expires; then it is, and the orphan purge removes it.
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

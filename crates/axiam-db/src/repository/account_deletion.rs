//! SurrealDB implementation of [`AccountDeletionRepository`].

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::id::new_id;
use axiam_core::models::gdpr::{AccountDeletion, AccountDeletionStatus, CreateAccountDeletion};
use axiam_core::provisioning::ProvisioningSink;
use axiam_core::repository::AccountDeletionRepository;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{
    CountRow, TxFail, classify_write_error, parse_uuid, retry_hot_row, retry_on_write_conflict,
};

// ---------------------------------------------------------------------------
// Row structs
// ---------------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct AccountDeletionRow {
    tenant_id: String,
    user_id: String,
    cancel_token_hash: String,
    scheduled_purge_at: DateTime<Utc>,
    status: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct AccountDeletionRowWithId {
    record_id: String,
    tenant_id: String,
    user_id: String,
    cancel_token_hash: String,
    scheduled_purge_at: DateTime<Utc>,
    status: String,
    created_at: DateTime<Utc>,
}

fn parse_status(s: &str) -> Result<AccountDeletionStatus, DbError> {
    match s {
        "pending" => Ok(AccountDeletionStatus::Pending),
        "cancelled" => Ok(AccountDeletionStatus::Cancelled),
        "completed" => Ok(AccountDeletionStatus::Completed),
        other => Err(DbError::Migration(format!(
            "unknown account_deletion status: {other}"
        ))),
    }
}

impl AccountDeletionRowWithId {
    fn try_into_domain(self) -> Result<AccountDeletion, DbError> {
        let id = parse_uuid(&self.record_id, "record_id")?;
        let tenant_id = parse_uuid(&self.tenant_id, "tenant_id")?;
        let user_id = parse_uuid(&self.user_id, "user_id")?;
        Ok(AccountDeletion {
            id,
            tenant_id,
            user_id,
            cancel_token_hash: self.cancel_token_hash,
            scheduled_purge_at: self.scheduled_purge_at,
            status: parse_status(&self.status)?,
            created_at: self.created_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

pub struct SurrealAccountDeletionRepository<C: Connection> {
    db: DbHandle<C>,
    /// Told when a deletion request disables the account (G-6, D-57).
    provisioning_sink: Option<Arc<dyn ProvisioningSink>>,
}

impl<C: Connection> Clone for SurrealAccountDeletionRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            provisioning_sink: self.provisioning_sink.clone(),
        }
    }
}

impl<C: Connection> SurrealAccountDeletionRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        let db = db.into();
        Self {
            db,
            provisioning_sink: None,
        }
    }

    /// Report the account a deletion request disables to `sink` (G-6, D-57).
    ///
    /// [`Self::create_with_pending_flag`] writes the user row's `status`
    /// (`Inactive`) in its own transaction, outside `SurrealUserRepository`, so
    /// the repository that owns the write has to announce it.
    #[must_use]
    pub fn with_provisioning_sink(mut self, sink: Arc<dyn ProvisioningSink>) -> Self {
        self.provisioning_sink = Some(sink);
        self
    }

    /// Find a pending deletion request by user_id within a tenant.
    ///
    /// Used by the purge sweep to mark the deletion row as completed once
    /// the purge pipeline finishes.
    pub async fn find_pending_by_user_id(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AxiamResult<Option<AccountDeletion>> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM account_deletion \
                 WHERE tenant_id = $tenant_id AND user_id = $user_id AND status = 'pending'",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<AccountDeletionRowWithId> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .map(|r| r.try_into_domain().map_err(Into::into))
            .transpose()
    }

    /// Look up a pending deletion by token hash without requiring tenant_id.
    ///
    /// Used by the public cancel endpoint where the caller is not authenticated
    /// and the tenant_id is not in the request context (D-09).  The token hash
    /// uniqueness enforced by the UNIQUE index makes cross-tenant collision
    /// practically impossible.
    pub async fn find_by_token_hash_global(
        &self,
        cancel_token_hash: &str,
    ) -> AxiamResult<Option<AccountDeletion>> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM account_deletion \
                 WHERE cancel_token_hash = $hash",
            )
            .bind(("hash", cancel_token_hash.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<AccountDeletionRowWithId> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .map(|r| r.try_into_domain().map_err(Into::into))
            .transpose()
    }

    /// D-14: atomically mark a user deletion-pending AND create the
    /// `account_deletion` row (holding the `cancel_token_hash`) in ONE
    /// transaction.
    ///
    /// Before this method existed, `gdpr.rs::request_account_delete` issued
    /// two fully independent DB round-trips — `user_repo.mark_deletion_pending`
    /// then `account_deletion_repo.create` — so a failure on the second call
    /// (after the first already committed) left the user permanently
    /// `deletion_pending = true` with no `account_deletion` row to hold a
    /// cancel token: an uncancellable purge (CQ-B39 residual). Wrapping both
    /// statements in `BEGIN`/`COMMIT` guarantees they succeed or fail
    /// together.
    ///
    /// Also adds a duplicate-pending-request guard (Rule 2: without it, a
    /// double-submit race could mint two live `account_deletion` rows — two
    /// outstanding cancel tokens — for the same user). The guard is
    /// evaluated *inside* the same transaction: if a pending deletion
    /// already exists for this user, the whole transaction — including the
    /// just-issued `UPDATE` on the user row — rolls back, so
    /// `deletion_pending` is never left `true` without a matching
    /// cancellable row.
    ///
    /// Result slots: BEGIN=0, UPDATE user=1, LET $existing=2, IF/THROW=3,
    /// CREATE account_deletion=4, COMMIT=5. Every field of the returned
    /// `AccountDeletion` is already known client-side (the id is generated
    /// here, everything else is an input or a literal), so we don't
    /// `.take()` any statement result — `.check()` alone proves the whole
    /// transaction committed.
    pub async fn create_with_pending_flag(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        scheduled_purge_at: DateTime<Utc>,
        cancel_token_hash: String,
    ) -> AxiamResult<AccountDeletion> {
        let id = new_id();
        let created_at = Utc::now();

        let query = "BEGIN TRANSACTION; \
            UPDATE type::record('user', $user_id) SET \
                deletion_pending = true, \
                scheduled_purge_at = $purge_at, \
                status = 'Inactive', \
                updated_at = time::now() \
                WHERE tenant_id = $tenant_id; \
            LET $existing = (SELECT id FROM account_deletion \
                WHERE tenant_id = $tenant_id AND user_id = $user_id \
                AND status = 'pending'); \
            IF array::len($existing) > 0 { \
                THROW 'pending deletion request already exists'; \
            }; \
            CREATE type::record('account_deletion', $ad_id) SET \
                tenant_id = $tenant_id, \
                user_id = $user_id, \
                cancel_token_hash = $hash, \
                scheduled_purge_at = $purge_at, \
                status = 'pending', \
                created_at = $created_at; \
            COMMIT TRANSACTION";

        let result = self
            .db
            .current()
            .query(query)
            .bind(("user_id", user_id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("purge_at", scheduled_purge_at))
            .bind(("ad_id", id.to_string()))
            .bind(("hash", cancel_token_hash.clone()))
            .bind(("created_at", created_at))
            .await
            .map_err(DbError::from)?;

        result
            .check()
            .map_err(|e| classify_write_error(e.to_string(), "account_deletion"))?;

        // The user is `Inactive` now: a provisioned field changed.
        if let Some(sink) = &self.provisioning_sink {
            sink.user_changed(tenant_id, user_id).await;
        }
        Ok(AccountDeletion {
            id,
            tenant_id,
            user_id,
            cancel_token_hash,
            scheduled_purge_at,
            status: AccountDeletionStatus::Pending,
            created_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Cancel vs. purge (item 11 of the 1.1.0 atomicity audit)
// ---------------------------------------------------------------------------
//
// A cancel and the purge sweep decided on reads made before their writes, and
// every write was unconditional: a cancel that read "pending, inside the grace
// window" just before the deadline could land after the sweep had selected the
// account, and the caller was told "cancelled" while the sweep erased the
// account — or, worse, after the sweep had already revoked its credentials,
// group memberships, roles and certificates, which a cancel does not restore.
//
// Now the sweep **claims** a request before its first destructive step
// (`claim_for_purge`: `purge_claimed_at`, schema v107, written in a transaction
// that re-checks the account is still due), and a cancel is one transaction
// that re-checks the request is pending, unclaimed and inside its window, and
// then clears the account's pending flag (`cancel_pending`). Both write the
// `account_deletion` row, so the engine serialises them: a claim committed
// first makes the cancel answer [`CancelOutcome::Erasing`]; a cancel committed
// first makes the claim find the account no longer due, and the sweep skips
// it. The loser of an overlap is retried on a fresh snapshot, where its
// re-check sees the winner.
//
// The claim is also exclusive (#738): every replica runs the sweep, and a
// claim was idempotent, so two sweeps that read one due account both ran its
// erasure. Now a claim younger than the lease answers `Held` to a second
// claimant, and the unit releases it on every exit before the anonymization.

const DELETION_GONE: &str = "axiam:account_deletion_gone";
const DELETION_CANCELLED: &str = "axiam:account_deletion_cancelled";
const DELETION_ERASING: &str = "axiam:account_deletion_erasing";
const DELETION_EXPIRED: &str = "axiam:account_deletion_expired";
const PURGE_NOT_DUE: &str = "axiam:account_purge_not_due";
const PURGE_HELD: &str = "axiam:account_purge_held";

/// What a cancel that is no longer possible answers through
/// [`AccountDeletionRepository::mark_cancelled`].
const NOT_CANCELLABLE: &str = "the deletion request is no longer pending: it was cancelled already, or its erasure has \
     started";

/// What [`SurrealAccountDeletionRepository::claim_for_purge`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeClaimOutcome {
    /// The claim is this caller's, stamped with its `now`, until it erases the
    /// account, releases the claim, or the lease runs out.
    Claimed,
    /// The account is no longer deletion-pending and due: its deletion was
    /// cancelled, or another unit has erased it.
    NotDue,
    /// Another unit holds a claim on the account younger than the lease.
    Held,
}

/// What [`SurrealAccountDeletionRepository::cancel_pending`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelOutcome {
    /// The request is cancelled and the account active again.
    Cancelled,
    /// The request was cancelled before; nothing changed.
    AlreadyCancelled,
    /// The grace window has ended; nothing changed.
    Expired,
    /// The purge sweep has claimed the request (or completed it): the erasure
    /// has started, and nothing changed.
    Erasing,
}

impl<C: Connection> SurrealAccountDeletionRepository<C> {
    /// Cancel the pending deletion request `id`, and re-enable its account, as
    /// one transaction — or say why not.
    ///
    /// The request must still be `pending`, unclaimed by the purge sweep
    /// (`purge_claimed_at = NONE`) and inside its grace window when the
    /// transaction runs, and the account must still be deletion-pending; the
    /// checks and both writes are one transaction. `NotFound` when there is no
    /// such request in the tenant.
    pub async fn cancel_pending(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<CancelOutcome> {
        let outcome = retry_on_write_conflict(|| self.cancel_tx(tenant_id, id))
            .await
            .map_err(AxiamError::from)?;
        if let (CancelOutcome::Cancelled, Some(sink), Some(user_id)) =
            (outcome.0, &self.provisioning_sink, outcome.1)
        {
            // The account is `Active` again: a provisioned field changed.
            sink.user_changed(tenant_id, user_id).await;
        }
        Ok(outcome.0)
    }

    async fn cancel_tx(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<(CancelOutcome, Option<Uuid>), TxFail> {
        // Slots: BEGIN=0, LET $row=1, four IF/THROW=2..=5, UPDATE deletion=6,
        // LET $user=7, IF/THROW=8, $user=9, COMMIT=10.
        let query = format!(
            "BEGIN TRANSACTION; \
             LET $row = (SELECT status, purge_claimed_at, scheduled_purge_at, user_id \
                 FROM type::record('account_deletion', $id) WHERE tenant_id = $tenant_id); \
             IF array::len($row) = 0 {{ THROW '{DELETION_GONE}'; }}; \
             IF $row[0].status = 'cancelled' {{ THROW '{DELETION_CANCELLED}'; }}; \
             IF $row[0].status != 'pending' OR $row[0].purge_claimed_at != NONE \
                 {{ THROW '{DELETION_ERASING}'; }}; \
             IF $row[0].scheduled_purge_at <= time::now() {{ THROW '{DELETION_EXPIRED}'; }}; \
             UPDATE type::record('account_deletion', $id) SET status = 'cancelled'; \
             LET $user = (UPDATE type::record('user', $row[0].user_id) SET \
                 deletion_pending = false, scheduled_purge_at = NONE, status = 'Active', \
                 updated_at = time::now() \
                 WHERE tenant_id = $tenant_id AND deletion_pending = true \
                 RETURN VALUE meta::id(id)); \
             IF array::len($user) = 0 {{ THROW '{DELETION_ERASING}'; }}; \
             $user; \
             COMMIT TRANSACTION"
        );
        let mut result = self
            .db
            .current()
            .query(query)
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await?;
        let errors = result.take_errors();
        if !errors.is_empty() {
            let combined = errors
                .into_values()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            if combined.contains(DELETION_GONE) {
                return Err(TxFail::Refused(AxiamError::NotFound {
                    entity: "account_deletion".into(),
                    id: id.to_string(),
                }));
            }
            // The refusals are matched before anything else: the statements
            // after a THROW report "not executed due to a failed transaction",
            // which is also a write-conflict marker.
            let refused = if combined.contains(DELETION_CANCELLED) {
                CancelOutcome::AlreadyCancelled
            } else if combined.contains(DELETION_ERASING) {
                CancelOutcome::Erasing
            } else if combined.contains(DELETION_EXPIRED) {
                CancelOutcome::Expired
            } else {
                return Err(TxFail::Db(classify_write_error(
                    combined,
                    "account_deletion",
                )));
            };
            return Ok((refused, None));
        }
        let users: Vec<String> = result.take(9).map_err(DbError::from)?;
        let user_id = users.first().map(|u| parse_uuid(u, "user")).transpose()?;
        Ok((CancelOutcome::Cancelled, user_id))
    }

    /// Claim `user_id`'s erasure for the purge sweep, before its first
    /// destructive step, exclusively and for `lease` (#738).
    ///
    /// [`PurgeClaimOutcome::NotDue`] when the account is no longer
    /// deletion-pending and due at `now` (its deletion was cancelled since the
    /// sweep's read), and [`PurgeClaimOutcome::Held`] when another unit holds a
    /// claim on it younger than `lease`: the sweep skips the account either
    /// way. Otherwise the claim is taken, stamped with `now`, and the answer is
    /// [`PurgeClaimOutcome::Claimed`].
    ///
    /// The claim lives on the pending request, as `purge_claimed_at`; an
    /// erasure without a request row is claimed by the same stamp on the user
    /// row, in `erasure_audit_pending` — the field the anonymization overwrites
    /// with its record marker, and the recovery reads only on an `Anonymized`
    /// row, so a claim on an account not yet erased is never taken for an owed
    /// record. A claim is free when its stamp is `NONE`, released (the Unix
    /// epoch, [`Self::release_purge_claim`]) or at or before `now - lease`:
    /// two sweeps that read one due account both reach this transaction, the
    /// engine serialises their writes to the one row, and the second, retried
    /// on a fresh snapshot, finds the first's claim live.
    ///
    /// Once claimed, a request can no longer be cancelled, released or not:
    /// the steps before the point of no return revoke what a cancel does not
    /// restore.
    pub async fn claim_for_purge(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        now: DateTime<Utc>,
        lease: chrono::TimeDelta,
    ) -> AxiamResult<PurgeClaimOutcome> {
        retry_on_write_conflict(|| self.claim_tx(tenant_id, user_id, now, lease))
            .await
            .map_err(AxiamError::from)
    }

    async fn claim_tx(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        now: DateTime<Utc>,
        lease: chrono::TimeDelta,
    ) -> Result<PurgeClaimOutcome, TxFail> {
        // A pending request is the claim's home; the user row's stamp stands
        // in only where there is none. A live stamp on either holds the
        // account, so a request created after a user-row claim does not open
        // a second way in.
        let query = format!(
            "BEGIN TRANSACTION; \
             LET $due = (SELECT VALUE meta::id(id) FROM type::record('user', $user_id) \
                 WHERE tenant_id = $tenant_id AND deletion_pending = true \
                 AND scheduled_purge_at <= $now); \
             IF array::len($due) = 0 {{ THROW '{PURGE_NOT_DUE}'; }}; \
             LET $held = (SELECT VALUE meta::id(id) FROM account_deletion \
                 WHERE tenant_id = $tenant_id AND user_id = $user_id AND status = 'pending' \
                 AND purge_claimed_at != NONE AND purge_claimed_at > $cutoff); \
             LET $user_held = (SELECT VALUE meta::id(id) FROM type::record('user', $user_id) \
                 WHERE erasure_audit_pending != NONE AND erasure_audit_pending > $cutoff); \
             IF array::len($held) > 0 OR array::len($user_held) > 0 \
                 {{ THROW '{PURGE_HELD}'; }}; \
             LET $taken = (UPDATE account_deletion SET purge_claimed_at = $now \
                 WHERE tenant_id = $tenant_id AND user_id = $user_id AND status = 'pending' \
                 RETURN VALUE meta::id(id)); \
             IF array::len($taken) = 0 {{ \
                 UPDATE type::record('user', $user_id) SET erasure_audit_pending = $now \
                 WHERE tenant_id = $tenant_id RETURN NONE; \
             }}; \
             COMMIT TRANSACTION"
        );
        let mut result = self
            .db
            .current()
            .query(query)
            .bind(("user_id", user_id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("now", now))
            .bind(("cutoff", now - lease))
            .await?;
        let errors = result.take_errors();
        if errors.is_empty() {
            return Ok(PurgeClaimOutcome::Claimed);
        }
        let combined = errors
            .into_values()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        // The refusals first: the statements after a THROW report "not
        // executed due to a failed transaction", a write-conflict marker too.
        if combined.contains(PURGE_NOT_DUE) {
            return Ok(PurgeClaimOutcome::NotDue);
        }
        if combined.contains(PURGE_HELD) {
            return Ok(PurgeClaimOutcome::Held);
        }
        Err(TxFail::Db(classify_write_error(
            combined,
            "account_deletion",
        )))
    }

    /// Give up the claim `stamp` on `user_id`'s erasure without erasing it,
    /// so the next sweep takes the account at once rather than after the
    /// lease (#738): the request's `purge_claimed_at` becomes the Unix epoch —
    /// older than any lease, and still not `NONE`, so the request stays
    /// uncancellable — and a user-row stamp is cleared.
    ///
    /// Only while the account is still deletion-pending: once the
    /// anonymization — the point of no return — has cleared that flag, the
    /// user row's `erasure_audit_pending` is the erasure's record marker, not
    /// this claim, and is left alone; so is a claim another unit has since
    /// taken over, which carries a different stamp.
    ///
    /// # Errors
    ///
    /// A datastore failure; the claim then lapses with its lease.
    pub async fn release_purge_claim(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        stamp: DateTime<Utc>,
    ) -> AxiamResult<()> {
        retry_on_write_conflict(|| async {
            let mut result = self
                .db
                .current()
                .query(
                    "BEGIN TRANSACTION; \
                     LET $due = (SELECT VALUE meta::id(id) FROM type::record('user', $user_id) \
                         WHERE tenant_id = $tenant_id AND deletion_pending = true); \
                     IF array::len($due) > 0 { \
                         UPDATE account_deletion SET purge_claimed_at = $epoch \
                         WHERE tenant_id = $tenant_id AND user_id = $user_id \
                           AND status = 'pending' AND purge_claimed_at = $stamp RETURN NONE; \
                         UPDATE type::record('user', $user_id) SET erasure_audit_pending = NONE \
                         WHERE tenant_id = $tenant_id AND deletion_pending = true \
                           AND erasure_audit_pending = $stamp RETURN NONE; \
                     }; \
                     COMMIT TRANSACTION;",
                )
                .bind(("user_id", user_id.to_string()))
                .bind(("tenant_id", tenant_id.to_string()))
                .bind(("stamp", stamp))
                .bind(("epoch", DateTime::<Utc>::UNIX_EPOCH))
                .await?;
            let errors = result.take_errors();
            if errors.is_empty() {
                return Ok(());
            }
            let combined = errors
                .into_values()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            Err(TxFail::Db(classify_write_error(
                combined,
                "account_deletion",
            )))
        })
        .await
        .map_err(AxiamError::from)
    }
}

/// An erasure whose `gdpr.user_pseudonymized` record is owed (#689), claimed by
/// [`SurrealAccountDeletionRepository::claim_owed_erasure_records`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwedErasureRecord {
    /// The erased account's tenant.
    pub tenant_id: Uuid,
    /// The erased account.
    pub user_id: Uuid,
    /// Its GDPR pseudonym, as the anonymization wrote it over the username.
    pub pseudonym: String,
    /// The claim this call holds on the account's marker.
    pub claimed_at: DateTime<Utc>,
}

/// The erasure-record marker, `user.erasure_audit_pending` (#689, schema v108).
///
/// The anonymization — the erasure's point of no return — sets it to its own
/// time in its own transaction (`SurrealUserRepository::anonymize_user`); the
/// value is the claim's stamp. The erasure reads it back
/// ([`Self::erasure_record_stamp`]), writes `gdpr.user_pseudonymized`, and
/// then clears it, completing the account's deletion request in the same
/// transaction ([`Self::settle_erasure_record`]). An erasure cut in between
/// leaves it set, and the next GDPR sweep, on any replica, claims it
/// ([`Self::claim_owed_erasure_records`]) once it is released
/// ([`Self::release_erasure_record`]: the Unix epoch) or older than the lease,
/// writes the record unless it is already there
/// ([`Self::erasure_recorded`]), and settles it. Every write is conditional
/// on the stamp read, so the erasure and a sweep, or two sweeps, never both
/// own the marker.
impl<C: Connection> SurrealAccountDeletionRepository<C> {
    /// The stamp of `user_id`'s erasure-record marker, `None` when no record
    /// is owed (or the account is not in `tenant_id`).
    ///
    /// # Errors
    ///
    /// A datastore failure.
    pub async fn erasure_record_stamp(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AxiamResult<Option<DateTime<Utc>>> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT VALUE erasure_audit_pending FROM type::record('user', $user_id) \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("user_id", user_id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(DbError::from)?;
        let stamps: Vec<Option<DateTime<Utc>>> = result.take(0).map_err(DbError::from)?;
        Ok(stamps.into_iter().next().flatten())
    }

    /// The erasure's record is written: clear `user_id`'s marker and, in the
    /// same transaction, complete its pending deletion request — only while
    /// the marker still carries `stamp`, the claim the caller holds. `true`
    /// when this call cleared it; `false` when the marker was taken over (the
    /// replica that took it settles it) or is already clear.
    ///
    /// # Errors
    ///
    /// A datastore failure; nothing changed, and the next sweep finds the
    /// record written and settles the marker.
    pub async fn settle_erasure_record(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        stamp: DateTime<Utc>,
    ) -> AxiamResult<bool> {
        retry_on_write_conflict(|| self.settle_tx(tenant_id, user_id, stamp))
            .await
            .map_err(AxiamError::from)
    }

    async fn settle_tx(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        stamp: DateTime<Utc>,
    ) -> Result<bool, TxFail> {
        let mut result = self
            .db
            .current()
            .query(
                "BEGIN TRANSACTION; \
                 LET $cleared = (UPDATE type::record('user', $user_id) \
                     SET erasure_audit_pending = NONE \
                     WHERE tenant_id = $tenant_id AND erasure_audit_pending = $stamp \
                     RETURN VALUE meta::id(id)); \
                 IF array::len($cleared) > 0 { \
                     UPDATE account_deletion SET status = 'completed' \
                     WHERE tenant_id = $tenant_id AND user_id = $user_id \
                       AND status = 'pending' RETURN NONE; \
                 }; \
                 RETURN array::len($cleared); \
                 COMMIT TRANSACTION;",
            )
            .bind(("user_id", user_id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("stamp", stamp))
            .await?;
        let errors = result.take_errors();
        if !errors.is_empty() {
            let combined = errors
                .into_values()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(TxFail::Db(classify_write_error(combined, "user")));
        }
        let cleared: Option<i64> = result.take(3)?;
        Ok(cleared.unwrap_or(0) > 0)
    }

    /// Give up the claim `stamp` on `user_id`'s marker without recording it,
    /// so the next sweep takes it over at once rather than after the lease: the
    /// stamp becomes the Unix epoch, older than any lease. A marker another
    /// replica has since taken over carries a different stamp and is left
    /// alone.
    ///
    /// # Errors
    ///
    /// A datastore failure; the marker then lapses with its lease.
    pub async fn release_erasure_record(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        stamp: DateTime<Utc>,
    ) -> AxiamResult<()> {
        retry_hot_row(|| async {
            self.db
                .current()
                .query(
                    "UPDATE type::record('user', $user_id) SET erasure_audit_pending = $epoch \
                     WHERE tenant_id = $tenant_id AND erasure_audit_pending = $stamp",
                )
                .bind(("user_id", user_id.to_string()))
                .bind(("tenant_id", tenant_id.to_string()))
                .bind(("stamp", stamp))
                .bind(("epoch", DateTime::<Utc>::UNIX_EPOCH))
                .await
                .map_err(DbError::from)?
                .check()
                .map_err(|e| classify_write_error(e, "user"))?;
            Ok::<_, DbError>(())
        })
        .await
        .map_err(Into::into)
    }

    /// Claim, at `now`, every erasure whose record is owed and that nobody is
    /// recording: an anonymized account whose marker is released or stamped at
    /// or before `now - lease`, and (#689 (i)) an anonymized account with no
    /// marker whose deletion request is still pending — an erasure cut before
    /// schema v108 between its anonymization and its completion. Each claim
    /// stamps the marker with `now`, conditionally on the value read, so of
    /// two sweeps that read one account exactly one takes it. What is returned
    /// is this call's to record, then to settle
    /// ([`Self::settle_erasure_record`]) or give up
    /// ([`Self::release_erasure_record`]).
    ///
    /// # Errors
    ///
    /// A datastore failure.
    pub async fn claim_owed_erasure_records(
        &self,
        now: DateTime<Utc>,
        lease: chrono::TimeDelta,
    ) -> AxiamResult<Vec<OwedErasureRecord>> {
        #[derive(Debug, SurrealValue)]
        struct OwedRow {
            record_id: String,
            tenant_id: String,
            username: String,
            stamp: Option<DateTime<Utc>>,
        }
        let mut result = self
            .db
            .current()
            .query(
                // The pending requests are read once into `$pending` and their
                // users fetched by record id: the cost follows the requests,
                // not the users (R111W1-01 — a subquery in the `WHERE` of a
                // scan of `user` is evaluated again for every row).
                "LET $pending = (SELECT VALUE user_id FROM account_deletion \
                     WHERE status = 'pending'); \
                 SELECT meta::id(id) AS record_id, tenant_id, username, \
                     erasure_audit_pending AS stamp \
                 FROM user WHERE erasure_audit_pending != NONE \
                   AND erasure_audit_pending <= $cutoff AND status = 'Anonymized'; \
                 SELECT meta::id(id) AS record_id, tenant_id, username, \
                     erasure_audit_pending AS stamp \
                 FROM array::map($pending, |$u| type::record('user', $u)) \
                 WHERE status = 'Anonymized' AND erasure_audit_pending = NONE;",
            )
            .bind(("cutoff", now - lease))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(DbError::from)?;
        let mut owed: Vec<OwedRow> = result.take(1).map_err(DbError::from)?;
        let unmarked: Vec<OwedRow> = result.take(2).map_err(DbError::from)?;
        owed.extend(unmarked);

        let mut claimed = Vec::new();
        for row in owed {
            let (Ok(user_id), Ok(tenant_id)) = (
                Uuid::parse_str(&row.record_id),
                Uuid::parse_str(&row.tenant_id),
            ) else {
                continue;
            };
            // Conditional on the marker read: NONE, or the stale stamp.
            let condition = if row.stamp.is_some() {
                "erasure_audit_pending = $read"
            } else {
                "erasure_audit_pending = NONE"
            };
            let statement = format!(
                "UPDATE type::record('user', $user_id) SET erasure_audit_pending = $now \
                 WHERE tenant_id = $tenant_id AND status = 'Anonymized' AND {condition} \
                 RETURN VALUE meta::id(id)"
            );
            let won = retry_hot_row(|| async {
                let mut result = self
                    .db
                    .current()
                    .query(statement.as_str())
                    .bind(("user_id", row.record_id.clone()))
                    .bind(("tenant_id", row.tenant_id.clone()))
                    .bind(("now", now))
                    .bind(("read", row.stamp))
                    .await
                    .map_err(DbError::from)?
                    .check()
                    .map_err(|e| classify_write_error(e, "user"))?;
                let ids: Vec<String> = result.take(0).map_err(DbError::from)?;
                Ok::<_, DbError>(!ids.is_empty())
            })
            .await?;
            if won {
                claimed.push(OwedErasureRecord {
                    tenant_id,
                    user_id,
                    pseudonym: row.username,
                    claimed_at: now,
                });
            }
        }
        Ok(claimed)
    }

    /// Whether `tenant_id`'s audit trail holds `action` written with
    /// `user_id` as its actor — for `gdpr.user_pseudonymized`, whether the
    /// erasure's record was written before its marker could be cleared
    /// (#689). An account is erased once, so the first such row is the one.
    ///
    /// # Errors
    ///
    /// A datastore failure.
    pub async fn erasure_recorded(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        action: &str,
    ) -> AxiamResult<bool> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM audit_log \
                 WHERE tenant_id = $tenant_id AND actor_id = $user_id AND action = $action \
                 GROUP ALL",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .bind(("action", action.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(DbError::from)?;
        let rows: Vec<CountRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows.first().is_some_and(|r| r.total > 0))
    }
}

impl<C: Connection> AccountDeletionRepository for SurrealAccountDeletionRepository<C> {
    async fn create(&self, input: CreateAccountDeletion) -> AxiamResult<AccountDeletion> {
        let id = new_id();
        let result = self
            .db
            .current()
            .query(
                "CREATE type::record('account_deletion', $id) SET \
                 tenant_id = $tenant_id, \
                 user_id = $user_id, \
                 cancel_token_hash = $cancel_token_hash, \
                 scheduled_purge_at = $scheduled_purge_at, \
                 status = 'pending', \
                 created_at = time::now()",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("user_id", input.user_id.to_string()))
            .bind(("cancel_token_hash", input.cancel_token_hash))
            .bind(("scheduled_purge_at", input.scheduled_purge_at))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<AccountDeletionRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "account_deletion".into(),
            id: id.to_string(),
        })?;

        Ok(AccountDeletion {
            id,
            tenant_id: input.tenant_id,
            user_id: input.user_id,
            cancel_token_hash: row.cancel_token_hash,
            scheduled_purge_at: row.scheduled_purge_at,
            status: parse_status(&row.status)?,
            created_at: row.created_at,
        })
    }

    async fn find_by_token_hash(
        &self,
        tenant_id: Uuid,
        cancel_token_hash: &str,
    ) -> AxiamResult<Option<AccountDeletion>> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM account_deletion \
                 WHERE tenant_id = $tenant_id AND cancel_token_hash = $hash",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("hash", cancel_token_hash.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<AccountDeletionRowWithId> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .map(|r| r.try_into_domain().map_err(Into::into))
            .transpose()
    }

    async fn mark_cancelled(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        let mut result = self
            .db
            .current()
            .query(
                "UPDATE type::record('account_deletion', $id) SET \
                 status = 'cancelled' \
                 WHERE tenant_id = $tenant_id AND status = 'pending' \
                 AND purge_claimed_at = NONE \
                 RETURN VALUE meta::id(id)",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        // Item 11 of the 1.1.0 atomicity audit: only a request still pending,
        // and not yet claimed by the purge sweep, is cancelled. Anything else
        // is not, and says so.
        let cancelled: Vec<String> = result.take(0).map_err(DbError::from)?;
        if cancelled.is_empty() {
            return Err(AxiamError::Conflict {
                reason: NOT_CANCELLABLE.into(),
            });
        }
        Ok(())
    }

    async fn mark_completed(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        self.db
            .current()
            .query(
                "UPDATE type::record('account_deletion', $id) SET \
                 status = 'completed' \
                 WHERE tenant_id = $tenant_id AND status = 'pending'",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::tenant::TenantKind;
    use axiam_test_support::test_password;
    use chrono::Duration;
    use surrealdb::Surreal;
    use surrealdb::engine::local::Mem;

    async fn setup_db() -> Surreal<surrealdb::engine::local::Db> {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        crate::schema::run_migrations(&db).await.unwrap();
        db
    }

    #[tokio::test]
    async fn account_deletion_round_trip() {
        let db = setup_db().await;
        let repo = SurrealAccountDeletionRepository::new(db);
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let purge_at = Utc::now() + Duration::days(30);

        let req = repo
            .create(CreateAccountDeletion {
                tenant_id,
                user_id,
                cancel_token_hash: "sha256-of-token".into(),
                scheduled_purge_at: purge_at,
            })
            .await
            .unwrap();

        assert_eq!(req.status, AccountDeletionStatus::Pending);
        // Stores hash, not raw token
        assert_eq!(req.cancel_token_hash, "sha256-of-token");

        let found = repo
            .find_by_token_hash(tenant_id, "sha256-of-token")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, req.id);

        repo.mark_cancelled(tenant_id, req.id).await.unwrap();
        let found2 = repo
            .find_by_token_hash(tenant_id, "sha256-of-token")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found2.status, AccountDeletionStatus::Cancelled);
    }

    #[tokio::test]
    async fn find_by_token_hash_returns_none_when_missing() {
        let db = setup_db().await;
        let repo = SurrealAccountDeletionRepository::new(db);
        let found = repo
            .find_by_token_hash(Uuid::new_v4(), "no-such-hash")
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn mark_completed_transitions_status() {
        let db = setup_db().await;
        let repo = SurrealAccountDeletionRepository::new(db);
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let purge_at = Utc::now() + Duration::days(30);

        let req = repo
            .create(CreateAccountDeletion {
                tenant_id,
                user_id,
                cancel_token_hash: "hash-complete".into(),
                scheduled_purge_at: purge_at,
            })
            .await
            .unwrap();

        repo.mark_completed(tenant_id, req.id).await.unwrap();
        let found = repo
            .find_by_token_hash(tenant_id, "hash-complete")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.status, AccountDeletionStatus::Completed);
    }

    #[tokio::test]
    async fn find_pending_by_user_id_only_returns_pending_status() {
        let db = setup_db().await;
        let repo = SurrealAccountDeletionRepository::new(db);
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let purge_at = Utc::now() + Duration::days(30);

        // No pending request yet.
        assert!(
            repo.find_pending_by_user_id(tenant_id, user_id)
                .await
                .unwrap()
                .is_none()
        );

        let req = repo
            .create(CreateAccountDeletion {
                tenant_id,
                user_id,
                cancel_token_hash: "hash-pending".into(),
                scheduled_purge_at: purge_at,
            })
            .await
            .unwrap();

        let found = repo
            .find_pending_by_user_id(tenant_id, user_id)
            .await
            .unwrap()
            .expect("pending deletion must be found");
        assert_eq!(found.id, req.id);

        // Once cancelled, it is no longer "pending".
        repo.mark_cancelled(tenant_id, req.id).await.unwrap();
        assert!(
            repo.find_pending_by_user_id(tenant_id, user_id)
                .await
                .unwrap()
                .is_none(),
            "a cancelled request must not be returned as pending"
        );
    }

    #[tokio::test]
    async fn find_by_token_hash_global_finds_across_tenants() {
        let db = setup_db().await;
        let repo = SurrealAccountDeletionRepository::new(db);
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let purge_at = Utc::now() + Duration::days(30);

        let req = repo
            .create(CreateAccountDeletion {
                tenant_id,
                user_id,
                cancel_token_hash: "global-hash".into(),
                scheduled_purge_at: purge_at,
            })
            .await
            .unwrap();

        // Found without needing to know the tenant_id.
        let found = repo
            .find_by_token_hash_global("global-hash")
            .await
            .unwrap()
            .expect("must find the row by hash alone");
        assert_eq!(found.id, req.id);

        let missing = repo
            .find_by_token_hash_global("no-such-hash-anywhere")
            .await
            .unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn create_with_pending_flag_sets_user_flag_and_creates_row_atomically() {
        use crate::repository::{
            SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
        };
        use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};

        let db = setup_db().await;

        // Seed a real user row so the transaction's UPDATE has a target.
        let org = SurrealOrganizationRepository::new(db.clone())
            .create(axiam_core::models::organization::CreateOrganization {
                name: "Org".into(),
                slug: "org".into(),
                metadata: None,
            })
            .await
            .unwrap();
        let tenant = SurrealTenantRepository::new(db.clone())
            .create(axiam_core::models::tenant::CreateTenant {
                organization_id: org.id,
                kind: TenantKind::Standard,
                name: "Tenant".into(),
                slug: "tenant".into(),
                metadata: None,
            })
            .await
            .unwrap();
        let user = SurrealUserRepository::new(db.clone())
            .create(axiam_core::models::user::CreateUser {
                tenant_id: tenant.id,
                username: "delete-me".into(),
                email: "delete-me@example.com".into(),
                password: test_password(),
                metadata: None,
            })
            .await
            .unwrap();

        let repo = SurrealAccountDeletionRepository::new(db.clone());
        let purge_at = Utc::now() + Duration::days(30);

        let deletion = repo
            .create_with_pending_flag(tenant.id, user.id, purge_at, "atomic-hash".into())
            .await
            .unwrap();
        assert_eq!(deletion.status, AccountDeletionStatus::Pending);
        assert_eq!(deletion.cancel_token_hash, "atomic-hash");

        // The user row must have been flipped to deletion_pending in the SAME
        // transaction (D-14).
        let user_repo = SurrealUserRepository::new(db.clone());
        let updated_user = user_repo.get_by_id(tenant.id, user.id).await.unwrap();
        assert!(updated_user.deletion_pending);

        // A second call for the SAME user while one is already pending must
        // roll back the whole transaction (duplicate-pending-request guard).
        let dup = repo
            .create_with_pending_flag(tenant.id, user.id, purge_at, "another-hash".into())
            .await;
        assert!(
            dup.is_err(),
            "a second pending deletion for the same user must be rejected"
        );

        // Exactly one account_deletion row must exist for this user.
        let pending = repo
            .find_pending_by_user_id(tenant.id, user.id)
            .await
            .unwrap()
            .expect("original pending row must still exist");
        assert_eq!(pending.cancel_token_hash, "atomic-hash");
    }
}

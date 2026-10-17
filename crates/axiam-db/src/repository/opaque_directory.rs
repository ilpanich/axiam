//! An enabled directory and `opaque_mode = required` never coexist, under
//! concurrency too (item 10 of the 1.1.0 atomicity audit).
//!
//! Under `required` a tenant refuses password sign-in before reading a
//! password, so a directory account — which has no OPAQUE record and never can
//! — could not sign in at all (G-3, CONTRACT §30.3 rule 3). Each side refuses
//! the other: a directory save that would leave an enabled directory reads the
//! tenant's effective settings, and a settings write that would make the mode
//! `required` reads the tenant's directory. Both reads were made before the
//! write, in statements of their own, and the two writes touch different rows
//! (`directory_config`, `security_settings`), so an enable and a `required`
//! sent together each passed on the other's "before" state and both landed —
//! leaving every directory account locked out.
//!
//! Both writes now claim `tenant.opaque_directory_epoch` (schema v106) the way
//! the network gate claims a role's epochs (#701): the handler reads the epoch
//! **before** the read its rule decides on ([`OpaqueDirectoryClaim`]), and the
//! write's own transaction compares it and moves it ([`claim_statement`]). A
//! claim that no longer matches — the other side committed since the read —
//! `THROW`s, and the caller answers `409` ("changed since it was read"). Two
//! overlapping claimed writes also write the same tenant row, so the engine
//! aborts one; it is retried on a fresh snapshot and its compare fails. The
//! next value is computed by the caller and only assigned in the `UPDATE`
//! (`role::bump_statement` gives the stack-depth reason).
//!
//! Only the writes that could break the rule claim: a directory save whose
//! result is enabled, and a settings write whose result is an effective
//! `required` — for an organization baseline, on every tenant of the
//! organization, and refused as stale when a tenant appeared since its read.

use axiam_core::error::AxiamError;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::helpers::{TxFail, classify_write_error};

/// `THROW`n by a claimed write whose tenant's epoch moved since the read.
const OPAQUE_DIRECTORY_STALE: &str = "axiam:opaque_directory_stale";

/// What a claimed write answers when it lost: the other side committed since
/// the caller's read.
pub const CHANGED_SINCE_READ: &str = "the tenant's directory or its opaque_mode changed since \
     this request read them; reload and retry";

/// The epoch a handler read for one tenant, before the read its rule decides
/// on. A claimed write compares it inside its own transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpaqueDirectoryClaim {
    /// The tenant claimed.
    pub tenant_id: Uuid,
    /// `tenant.opaque_directory_epoch` as read (`NONE` reads as 0).
    pub epoch: i64,
}

#[derive(Debug, SurrealValue)]
pub(crate) struct ClaimRow {
    pub(crate) tenant_id: String,
    pub(crate) epoch: i64,
}

impl ClaimRow {
    pub(crate) fn into_claim(self) -> Result<OpaqueDirectoryClaim, DbError> {
        Ok(OpaqueDirectoryClaim {
            tenant_id: crate::helpers::parse_uuid(&self.tenant_id, "tenant")?,
            epoch: self.epoch,
        })
    }
}

/// The read a claim starts from, for the tenants a statement's `WHERE` names
/// (`$tenant_id` or `$org_id`). Live tenants only, as the tenant listing reads.
pub(crate) const READ_ONE: &str = "SELECT meta::id(id) AS tenant_id, \
     opaque_directory_epoch ?? 0 AS epoch FROM type::record('tenant', $tenant_id)";
pub(crate) const READ_ORG: &str = "SELECT meta::id(id) AS tenant_id, \
     opaque_directory_epoch ?? 0 AS epoch FROM tenant \
     WHERE organization_id = $org_id AND deleted_at = NONE";

/// The bound form of a set of claims: `[{tenant, epoch, next}]`.
pub(crate) fn bind_claims(claims: &[OpaqueDirectoryClaim]) -> serde_json::Value {
    serde_json::Value::Array(
        claims
            .iter()
            .map(|c| {
                serde_json::json!({
                    "tenant": c.tenant_id.to_string(),
                    "epoch": c.epoch,
                    "next": c.epoch + 1,
                })
            })
            .collect(),
    )
}

/// The statement that opens a claimed write: for each of `$opaque_claims`
/// ([`bind_claims`]), compare the tenant's epoch and move it. One result slot.
/// With `org_scoped`, a second statement pair (two more slots) refuses a write
/// whose organization holds a live tenant it did not claim — one created since
/// the read.
pub(crate) fn claim_statement(org_scoped: bool) -> String {
    let mut sql = format!(
        "FOR $claim IN $opaque_claims {{ \
             LET $held = (SELECT VALUE opaque_directory_epoch ?? 0 \
                 FROM type::record('tenant', $claim.tenant)); \
             IF array::len($held) = 0 OR $held[0] != $claim.epoch \
                 {{ THROW '{OPAQUE_DIRECTORY_STALE}'; }}; \
             UPDATE type::record('tenant', $claim.tenant) \
                 SET opaque_directory_epoch = $claim.next; \
         }}; "
    );
    if org_scoped {
        sql.push_str(&format!(
            "LET $unclaimed = (SELECT VALUE meta::id(id) FROM tenant \
                 WHERE organization_id = $org_id AND deleted_at = NONE \
                 AND meta::id(id) NOTINSIDE $opaque_claims.tenant); \
             IF array::len($unclaimed) > 0 {{ THROW '{OPAQUE_DIRECTORY_STALE}'; }}; "
        ));
    }
    sql
}

/// How many result slots [`claim_statement`] fills.
pub(crate) fn claim_slots(org_scoped: bool) -> usize {
    if org_scoped { 3 } else { 1 }
}

/// A claimed write's statement errors, read: the stale refusal first (see
/// [`TxFail`] for why the order matters), then what is left, classified.
pub(crate) fn outcome(
    errors: std::collections::HashMap<usize, surrealdb::Error>,
    entity: &str,
) -> Result<(), TxFail> {
    if errors.is_empty() {
        return Ok(());
    }
    let combined = errors
        .into_values()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("; ");
    if combined.contains(OPAQUE_DIRECTORY_STALE) {
        return Err(TxFail::Refused(AxiamError::Conflict {
            reason: CHANGED_SINCE_READ.into(),
        }));
    }
    Err(TxFail::Db(classify_write_error(combined, entity)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The slot count is what callers index the write after the claim by:
    /// the `FOR` is one statement whatever its body holds, and the organization
    /// check adds a `LET` and an `IF`.
    #[test]
    fn the_claim_fills_the_slots_it_declares() {
        for org_scoped in [false, true] {
            let sql = claim_statement(org_scoped);
            assert_eq!(sql.matches("FOR $claim").count(), 1);
            let org_statements = sql.matches("LET $unclaimed").count()
                + sql.matches("IF array::len($unclaimed)").count();
            assert_eq!(claim_slots(org_scoped), 1 + org_statements);
        }
        assert_eq!(claim_slots(true), 3);
    }

    #[test]
    fn a_claim_binds_its_next_epoch() {
        let tenant_id = Uuid::new_v4();
        let bound = bind_claims(&[OpaqueDirectoryClaim {
            tenant_id,
            epoch: 4,
        }]);
        assert_eq!(bound[0]["tenant"], tenant_id.to_string());
        assert_eq!(bound[0]["epoch"], 4);
        assert_eq!(bound[0]["next"], 5);
    }
}

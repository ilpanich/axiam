//! The daily cap on mailed tokens, counted inside the mint (item 7 of the
//! 1.1.0 atomicity audit).
//!
//! A password reset link and a resent verification link are each capped per
//! account per UTC day (`axiam_auth::password_reset`, `axiam_auth::verification`).
//! The cap was a count made before the mint, in a statement of its own: N
//! requests sent together each read a count under the cap and all minted, so
//! the cap was exceeded and — for a reset, which supersedes the account's
//! earlier links — more than one link was live.
//!
//! A capped mint is now one transaction: it counts the account's tokens of
//! that kind minted today, `THROW`s [`MAIL_DAILY_CAP_REACHED`] at the cap, and
//! writes `user.mail_epoch` (schema v104) before its own writes. SurrealDB
//! 3.3.4 is snapshot-isolated with write-write conflict detection only, so the
//! count alone would not do: N transactions that each counted under the cap
//! and each created a different token row would all commit. The shared write
//! on the user row is what makes two overlapping mints conflict; the loser is
//! retried on a fresh snapshot ([`crate::helpers::retry_hot_row`]), where its
//! count sees the winner's token. A refusal writes nothing, so it conflicts
//! with nothing. The epoch's next value is a `LET` of its own and the `UPDATE`
//! only assigns it, for the stack-depth reason `role::bump_statement` gives.

use chrono::{DateTime, Utc};

use crate::error::DbError;
use crate::helpers::classify_write_error;

/// `THROW`n by a capped mint when the account already has the day's cap of
/// tokens of that kind.
const MAIL_DAILY_CAP_REACHED: &str = "axiam:mail_daily_cap_reached";

/// `THROW`n by a capped mint whose account is not the tenant's (or no longer
/// exists): there is no row to claim, so nothing is minted.
const MAIL_CAP_NO_USER: &str = "axiam:mail_cap_no_user";

/// How many result slots [`claim`] fills.
pub(crate) const CLAIM_SLOTS: usize = 6;

/// The statements that open a capped mint of a `table` row (a UUID-free table
/// name this crate chose, never caller text). They read `$tenant_id`,
/// `$user_id`, `$day_start` and `$daily_cap` ([`day_start`]), and fill
/// [`CLAIM_SLOTS`] result slots.
pub(crate) fn claim(table: &str) -> String {
    format!(
        "LET $mail_epoch = (SELECT VALUE mail_epoch ?? 0 \
             FROM type::record('user', $user_id) WHERE tenant_id = $tenant_id); \
         IF array::len($mail_epoch) = 0 {{ THROW '{MAIL_CAP_NO_USER}'; }}; \
         LET $minted = (SELECT count() AS total FROM {table} \
             WHERE tenant_id = $tenant_id AND user_id = $user_id \
             AND created_at >= $day_start GROUP ALL); \
         IF ($minted[0].total ?? 0) >= $daily_cap {{ THROW '{MAIL_DAILY_CAP_REACHED}'; }}; \
         LET $next_mail_epoch = $mail_epoch[0] + 1; \
         UPDATE type::record('user', $user_id) SET mail_epoch = $next_mail_epoch; "
    )
}

/// Midnight UTC today: the start of the window the cap counts, the one each
/// repository's `count_today` counts.
pub(crate) fn day_start() -> DateTime<Utc> {
    Utc::now()
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .expect("midnight is always valid")
        .and_utc()
}

/// A capped mint's statement errors, read. `Ok(true)`: the cap was reached.
/// `Ok(false)`: nothing failed. `Err`: `NotFound` for an account that is not
/// the tenant's, otherwise what is left, classified — an engine conflict is
/// retried by the caller.
///
/// Every slot is read: a `THROW` fires on its own statement while the rest
/// report "not executed due to a failed transaction", which is also a
/// write-conflict marker — so the refusals are matched first.
pub(crate) fn outcome(
    errors: std::collections::HashMap<usize, surrealdb::Error>,
    entity: &str,
    user_id: &str,
) -> Result<bool, DbError> {
    if errors.is_empty() {
        return Ok(false);
    }
    let combined = errors
        .into_values()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("; ");
    if combined.contains(MAIL_DAILY_CAP_REACHED) {
        return Ok(true);
    }
    if combined.contains(MAIL_CAP_NO_USER) {
        return Err(DbError::NotFound {
            entity: "user".into(),
            id: user_id.to_owned(),
        });
    }
    Err(classify_write_error(combined, entity))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The claim's slot count is what the callers index the writes after it
    /// by; a statement added without moving it would read the wrong slot.
    #[test]
    fn the_claim_fills_the_slots_it_declares() {
        let claim = claim("password_reset_token");
        let statements: usize = ["LET $", "IF ", "UPDATE "]
            .iter()
            .map(|keyword| claim.matches(keyword).count())
            .sum();
        assert_eq!(statements, CLAIM_SLOTS);
    }
}

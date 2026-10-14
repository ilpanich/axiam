//! The purge's grace past a certificate's `notAfter` must cover the longest a
//! revocation list can keep naming it (R101W1-08, #621).
//!
//! The two numbers live in two crates that do not depend on each other:
//! `axiam-db` keeps a revoked certificate's row for
//! [`REVOCATION_GRACE_SECS`] past `notAfter` (the tenant purge's
//! `KEPT_REVOCATION` and the cleanup job's `PAST_REVOCATION_GRACE`), and
//! `axiam-pki` lets an operator set the list's `nextUpdate` interval as high as
//! [`MAX_CRL_NEXT_UPDATE_SECS`]. `axiam-server` sees both, so the test lives
//! here.

use axiam_db::repository::tenant_purge::{
    KEPT_REVOCATION, PAST_REVOCATION_GRACE, REVOCATION_GRACE_SECS,
};
use axiam_pki::crl::MAX_CRL_NEXT_UPDATE_SECS;

/// What the grace must leave beyond the longest list interval: a day for the
/// datastore's clock, which times the purge, against the replicas', which cut
/// the list's epochs. The figure `KEPT_REVOCATION` documents.
const CLOCK_MARGIN_SECS: u64 = 86_400;

/// `KEPT_REVOCATION`'s grace is at least `MAX_CRL_NEXT_UPDATE_SECS` plus
/// [`CLOCK_MARGIN_SECS`].
///
/// Why the interval, and why that margin — the rule is `crl.rs`'s
/// `RefreshEpoch::of` (design document §35, rule 4). Time is cut into refresh
/// epochs `E` seconds long, aligned to the Unix epoch, with `E = I / 2` for a
/// `nextUpdate` interval `I`. A list signed in the epoch starting at `s` names
/// every revoked certificate whose `notAfter` `t` is later than `s - E` (the
/// start of the previous epoch), so an entry stays on every list of its own
/// epoch and of the one after it, and leaves only when the epoch moves on.
///
/// The last list that names an entry is therefore the last one of the last
/// epoch with `s - E < t`, that is `s < t + E`. That epoch ends at `s + E`, so
/// strictly before `t + 2E = t + I`: an entry is on a list for fewer than `I`
/// seconds past its `notAfter`, and `I` is at most `MAX_CRL_NEXT_UPDATE_SECS`.
/// A row the purge deleted before `t + I` could leave the list mid-epoch,
/// changing it without moving its `thisUpdate`, which is what breaks the CRL
/// number every replica derives (#608).
///
/// The margin past `I` covers the clock: the purge compares `notAfter` with the
/// datastore's `time::now()`, while the epoch is cut by the replica that signs,
/// and the two can disagree by up to the margin. It is the one day
/// `KEPT_REVOCATION` documents.
///
/// With today's `MAX_CRL_NEXT_UPDATE_SECS` of seven days the sum is eight days
/// and the assertion holds with nothing to spare; raising the maximum without
/// raising `revocation_grace_days!` (in `tenant_purge.rs`) fails it.
#[test]
fn kept_revocation_covers_the_longest_crl_interval() {
    // `black_box`: the values are constants, and clippy would otherwise turn
    // the assertion into a compile-time one with no message.
    let grace = std::hint::black_box(REVOCATION_GRACE_SECS);
    let longest_interval = std::hint::black_box(MAX_CRL_NEXT_UPDATE_SECS);
    assert!(
        grace >= longest_interval + CLOCK_MARGIN_SECS,
        "the purge keeps a revoked certificate for {grace} s past notAfter, but a list can \
         name it for up to {longest_interval} s (the longest nextUpdate interval) and the \
         datastore clock needs {CLOCK_MARGIN_SECS} s more; raise `revocation_grace_days!` \
         in axiam-db's tenant_purge.rs"
    );
}

/// The SurrealQL conditions say what the number says: the macro that feeds
/// [`REVOCATION_GRACE_SECS`] also spells the queries, and this pins that the
/// text and the number have not been separated by an edit to one of them.
#[test]
fn the_purge_conditions_state_the_same_grace() {
    assert_eq!(REVOCATION_GRACE_SECS % 86_400, 0, "a whole number of days");
    let days = REVOCATION_GRACE_SECS / 86_400;
    let spelled = format!("time::now() - {days}d");
    assert!(
        KEPT_REVOCATION.ends_with(&spelled),
        "KEPT_REVOCATION: {KEPT_REVOCATION}"
    );
    assert!(
        PAST_REVOCATION_GRACE.ends_with(&spelled),
        "PAST_REVOCATION_GRACE: {PAST_REVOCATION_GRACE}"
    );
}

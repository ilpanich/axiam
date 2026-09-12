//! Shared repository utilities: common row types and helper functions
//! that were previously duplicated across every repo module.

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::repository::{PaginatedResult, Pagination};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

// ---------------------------------------------------------------------------
// CountRow — shared across all repos for paginated count queries
// ---------------------------------------------------------------------------

/// Row struct for `SELECT count() AS total ... GROUP ALL` queries.
///
/// Previously duplicated privately in every repository module (user.rs:148,
/// role.rs:53, …). This canonical version replaces all of those (CQ-B10).
#[derive(Debug, SurrealValue)]
pub struct CountRow {
    pub total: u64,
}

// ---------------------------------------------------------------------------
// parse_uuid — typed parse, no longer misusing DbError::Migration (CQ-B11)
// ---------------------------------------------------------------------------

/// Parse a UUID string coming out of SurrealDB, embedding the field name in
/// the error message for easier debugging.
///
/// Unlike the inline `Uuid::parse_str(..).map_err(|e| DbError::Migration(…))`
/// pattern scattered across ~25 repos, this function names the offending
/// field and reports a corrupt-data read as `DbError::Serialization` — a
/// malformed value coming back out of a read is not a schema-migration
/// failure (QUAL-03/D-10).
pub fn parse_uuid(s: &str, field: &str) -> Result<Uuid, DbError> {
    s.parse::<Uuid>()
        .map_err(|e| DbError::Serialization(format!("invalid {field} UUID: {e}")))
}

// ---------------------------------------------------------------------------
// classify_write_error — centralized index-violation detection (QUAL-03/D-09)
// ---------------------------------------------------------------------------

/// Classify a write-path error (from a `CREATE`/`RELATE` statement's
/// `.check()` or an upstream mapped error) into the correct [`DbError`]
/// variant.
///
/// Reuses the exact marker-string set already proven correct against this
/// codebase's SurrealDB version by `saml_replay.rs`, `federation_login_state.rs`,
/// and `seeder.rs`: a genuine unique/index violation surfaces one of
/// `"already contains"`, `"already exists"`, or `"unique"` in the error text.
/// Those map to [`DbError::AlreadyExists`] (→ HTTP 409). Anything else —
/// crucially including a DB outage/connection error, which contains none of
/// these markers — falls through to [`DbError::Migration`] (→ 5xx). A DB
/// outage must never be misclassified as a false 409.
///
/// Generic over `E: Display` (rather than a single concrete error type) so
/// the same centralized detector can be called uniformly from every
/// `.map_err` site on the write paths this phase routes through it,
/// regardless of whether the site's error came from `Response::check()`
/// (`surrealdb::Error`) or another fallible step in the same write path.
///
/// Per D-09, this is the ONLY place that inspects error text for these
/// markers — call sites must not add their own inline `contains(...)` checks.
pub fn classify_write_error<E: std::fmt::Display>(err: E, entity: &str) -> DbError {
    let msg = err.to_string();
    if is_unique_violation(&msg) {
        DbError::AlreadyExists {
            entity: entity.to_string(),
        }
    } else if is_write_conflict(&msg) {
        // Ordered AFTER the unique check on purpose. A UNIQUE violation is a
        // statement about the caller's request and must win: it is a 409 the
        // client can act on, and retrying it would only fail again identically.
        // A write conflict says nothing about the request — only that it lost a
        // race — so it is the weaker, more retryable classification of the two.
        DbError::Conflict(msg)
    } else {
        DbError::Migration(msg)
    }
}

/// Run `op`, retrying while it fails with a retryable write conflict.
///
/// This is the helper the [`WRITE_CONFLICT_MARKERS`] documentation has linked
/// to since the markers were introduced, and which was never actually defined:
/// [`MAX_WRITE_ATTEMPTS`], [`write_conflict_backoff`] and [`is_write_conflict`]
/// all shipped, tested, with exactly one hand-rolled loop assembling them (in
/// `UserRepository::increment_failed_logins`) and no way to reuse it. Every
/// other contended write therefore had no retry at all — which is how a
/// concurrent SCIM `PATCH /scim/v2/Users/{id}` came to answer HTTP 500 on 2.2%
/// of a benchmark flood, for a write the engine labelled retryable.
///
/// `op` is a closure rather than a future because a future is consumed by the
/// first `.await`: a retry needs a *new* one per attempt, and SurrealDB's
/// `bind` takes owned values, so each attempt must rebuild its own statement.
///
/// Generic over the error type rather than fixed to [`DbError`] because the two
/// kinds of call site disagree about it: a repository method that returns
/// `AxiamResult<T>` has already widened to `AxiamError` by the time it can fail,
/// while one working inside the db layer still holds a `DbError`. Both render
/// the engine's text, which is all the retry predicate reads, so neither has to
/// convert at the boundary just to be retried.
///
/// # Safety of replaying `op`
///
/// Only [`is_write_conflict`] is retried, and a conflicted transaction commits
/// NOTHING — that is what the abort means. So re-running `op` cannot
/// double-apply, even when the statement is not idempotent (`x += 1`). Every
/// other error returns on the first attempt, so an outage or a malformed
/// statement fails fast instead of slowly.
pub async fn retry_on_write_conflict<T, E, F, Fut>(mut op: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut attempt = 1;
    loop {
        match op().await {
            // Matched on the rendered message rather than on `DbError::Conflict`
            // because a conflict can arrive as any of three variants depending
            // on where in the write path it surfaced: `Conflict` from
            // `classify_write_error`, `Surreal` from a bare `DbError::from`, or
            // `Migration` from a call site that has not been routed through the
            // classifier. Every one of them renders the engine's own text, so
            // the message is the reliable discriminator; the variant is not.
            Err(e) if attempt < MAX_WRITE_ATTEMPTS && is_write_conflict(&e.to_string()) => {
                tokio::time::sleep(write_conflict_backoff(attempt)).await;
                attempt += 1;
            }
            outcome => return outcome,
        }
    }
}

// ---------------------------------------------------------------------------
// The unique-violation marker set — one definition, three classifiers (F5)
// ---------------------------------------------------------------------------

/// Substrings that identify a SurrealDB UNIQUE-index violation.
///
/// SurrealDB v3 reports one as ``Database index `idx_x_uniq` already contains
/// [...]``. `"already exists"` and `"unique"` are kept as fallbacks: they
/// covered earlier server versions and cost nothing to keep, and a conflict
/// this set fails to recognise is not a benign miss — it is a replayed
/// assertion accepted as fresh.
///
/// **The set is narrow on purpose.** Everything it does not match falls
/// through to a 5xx, and that is the safe direction: a datastore outage
/// contains none of these markers and must never be reported to a caller as
/// "that already exists" or "that was a replay". Widening this set trades a
/// clearer conflict message for the risk of answering an outage with a 409.
const UNIQUE_VIOLATION_MARKERS: [&str; 3] = ["already contains", "already exists", "unique"];

/// Whether a datastore error message reports a UNIQUE-index violation.
///
/// # Why this is a function and not three `contains` calls
///
/// [`classify_write_error`] has always documented itself as "the ONLY place
/// that inspects error text for these markers — call sites must not add their
/// own inline `contains(...)` checks" (D-09). Five call sites did anyway:
/// `saml_replay`, `amqp_nonce_replay`, `oauth2_proof_replay`,
/// `federation_login_state` and the REST bootstrap handler, each with the
/// three markers written out again and a comment pointing at one of the
/// others as its source of truth.
///
/// Nobody did that carelessly — the copies were kept deliberately identical,
/// and `oauth2_proof_replay` says so in as many words: "kept identical so the
/// three replay guards cannot drift into disagreeing about what a conflict
/// looks like." That is the correct worry and the wrong mechanism. Every one
/// of those five sites decides whether a replayed credential is refused or
/// accepted; a marker added to four of them is a security fix with a hole in
/// it, and no test would notice.
///
/// So the markers live here, once, and the five sites call one of the three
/// classifiers below. See `claude_dev/conflict-classification.md`, and
/// `scripts/check-conflict-markers.py`, which fails CI if a sixth inline copy
/// appears.
pub fn is_unique_violation(msg: &str) -> bool {
    UNIQUE_VIOLATION_MARKERS.iter().any(|m| msg.contains(m))
}

// ---------------------------------------------------------------------------
// Optimistic-concurrency write conflicts — transient, and explicitly retryable
// ---------------------------------------------------------------------------

/// Substrings that identify a SurrealDB optimistic-concurrency write conflict.
///
/// SurrealDB is optimistic: concurrent transactions touching the same record
/// both proceed, and the loser is aborted at commit with
/// ``There was a problem with the key-value store: Transaction conflict:
/// Transaction write conflict. This transaction can be retried`` (some
/// versions phrase it ``Failed to commit transaction due to a read or write
/// conflict``). Both phrasings are matched.
///
/// **This class of failure is not an error to report — it is an instruction to
/// retry**, and the datastore says so in the message itself. It is emphatically
/// NOT a [`is_unique_violation`]: no constraint was broken and nothing about
/// the caller's request was wrong; the write simply lost a race and never
/// committed. Because it commits nothing, replaying it cannot double-apply —
/// which is what makes [`retry_on_write_conflict`] safe even for a
/// non-idempotent statement like `failed_login_attempts += 1`.
///
/// # The last two markers, and why they were a hole
///
/// `"failed transaction"` and `"Failed to commit transaction"` were the ONLY
/// two literals [`is_transaction_conflict`] matched, in a set of its own. That
/// helper guards the single-use consume on four replay-sensitive paths —
/// `device_grant`, `permission_ticket`, `pushed_auth_request` and
/// `oauth2_auth_code` — and the message SurrealDB v3 actually emits for a
/// contended write (`Transaction conflict: Transaction write conflict. This
/// transaction can be retried`) contains neither of them. So the branch those
/// four paths rely on to answer "someone else got there first" could not fire
/// on the phrasing the deployed engine produces, and a correctly-refused
/// replay surfaced as a 500 instead of as "no row consumed".
///
/// That direction is fail-CLOSED — a 500 mints no token — so it was a
/// robustness defect rather than a security hole. But it is exactly the
/// drift-between-copies failure D-09 and `scripts/check-conflict-markers.py`
/// exist to prevent, and it survived because the two sets were never one set.
/// They are one set now, and [`is_transaction_conflict`] delegates here.
const WRITE_CONFLICT_MARKERS: [&str; 4] = [
    "Transaction conflict",
    "read or write conflict",
    "failed transaction",
    "Failed to commit transaction",
];

/// Whether a datastore error message reports a retryable write conflict.
///
/// Kept beside [`is_unique_violation`] and for the same reason (D-09): the
/// decision "was this transient?" is made from free error text, so it gets one
/// definition rather than a `contains(...)` at every hot-row write site.
pub fn is_write_conflict(msg: &str) -> bool {
    WRITE_CONFLICT_MARKERS.iter().any(|m| msg.contains(m))
}

/// How many attempts a contended write gets before its conflict surfaces.
///
/// Four is chosen against the shape of the failure rather than as a round
/// number: a conflict means some other writer *did* commit, so the contended
/// record is free almost immediately and the overwhelming majority of retries
/// succeed on the first one. The extra attempts cover a burst of writers
/// landing on the same record at once; past that, retrying is no longer
/// masking a race but hiding sustained contention that should surface.
///
/// Retrying only ever applies to [`is_write_conflict`]. Every other error — an
/// outage, a malformed statement, a constraint violation — must return on the
/// first attempt, so a hard failure is never turned into a slow one.
pub const MAX_WRITE_ATTEMPTS: u32 = 4;

/// How long to wait before write attempt `attempt + 1` (2 ms, 4 ms, 8 ms).
///
/// Not there to wait out the winner — it has already committed by the time the
/// loser learns it lost — but to stop a burst of contending writers from
/// re-colliding in lockstep on the retry.
pub fn write_conflict_backoff(attempt: u32) -> std::time::Duration {
    std::time::Duration::from_millis(1u64 << attempt.min(6))
}

/// Classify a failed single-use `CREATE` on a replay-guard table.
///
/// A UNIQUE violation here is not an error condition — it is the answer. The
/// row was already present, so the assertion / nonce / proof `jti` being
/// inserted has been seen before, and the caller must refuse it. Anything else
/// is a real datastore failure and propagates as [`AxiamError::Database`], so
/// an outage surfaces as a 5xx rather than as a silent "replay detected" that
/// would refuse legitimate traffic.
///
/// Used by all three replay repositories (`saml_replay`, `amqp_nonce_replay`,
/// `oauth2_proof_replay`), which is the point: there is one definition of what
/// a replay looks like.
pub fn classify_replay_write_error<E: std::fmt::Display>(err: E) -> AxiamError {
    let msg = err.to_string();
    if is_unique_violation(&msg) {
        AxiamError::ReplayDetected
    } else {
        AxiamError::Database(msg)
    }
}

/// Classify a failed `CREATE` where a UNIQUE violation means "already taken".
///
/// The [`AxiamError`]-returning counterpart to [`classify_write_error`], for
/// the write paths that build an `AxiamError` directly rather than a
/// [`DbError`]. `entity` names what collided and reaches the client in the
/// 409 body, so it should identify the constrained thing
/// (`"federation_login_state.state"`), not merely the table.
pub fn classify_conflict_write_error<E: std::fmt::Display>(err: E, entity: &str) -> AxiamError {
    let msg = err.to_string();
    if is_unique_violation(&msg) {
        AxiamError::AlreadyExists {
            entity: entity.to_string(),
        }
    } else {
        AxiamError::Database(msg)
    }
}

// ---------------------------------------------------------------------------
// cleanup_expired_rows — one sweep for every replay-guard table (F5)
// ---------------------------------------------------------------------------

/// Count and then delete every row of `table` whose `expires_at` has passed,
/// returning how many were removed.
///
/// The three replay tables carried a byte-identical copy of this, differing
/// only in the table name. It is not security-critical the way
/// [`classify_replay_write_error`] is — a sweep that under-deletes leaves rows
/// that only cost space, and the UNIQUE index keeps doing its job either way —
/// but three copies of one query is three places to fix when the count and the
/// delete need to become one statement.
///
/// `table` is interpolated into the query rather than bound, because SurrealDB
/// has no bind form for a table name. It is therefore **never** caller- or
/// request-derived: every call site passes a `&'static str` literal naming one
/// of this crate's own tables.
pub async fn cleanup_expired_rows<C: Connection>(
    db: &crate::handle::DbHandle<C>,
    table: &'static str,
) -> AxiamResult<u64> {
    let mut count_result = db
        .current()
        .query(format!(
            "SELECT count() AS total FROM {table} \
             WHERE expires_at < time::now() GROUP ALL"
        ))
        .await
        .map_err(DbError::from)?;

    let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;
    let total = count_rows.first().map(|r| r.total).unwrap_or(0);

    db.current()
        .query(format!("DELETE {table} WHERE expires_at < time::now()"))
        .await
        .map_err(DbError::from)?;

    Ok(total)
}

// ---------------------------------------------------------------------------
// take_first_or_not_found — unified "0 rows → NotFound" helper
// ---------------------------------------------------------------------------

/// Take the first element of `items` or return `DbError::NotFound`.
///
/// Replaces the `into_iter().next().ok_or_else(|| DbError::NotFound{…})`
/// pattern repeated in every `get_by_id` / find method.
/// Whether a SurrealDB error is a write-write transaction conflict.
///
/// # Why this exists
///
/// A multi-statement query (`LET $x = (UPDATE ...); SELECT ... FROM $x`) is
/// **not** atomic in SurrealDB — each statement runs in its own transaction —
/// so a single-use `UPDATE ... WHERE consumed = false` guard does not
/// serialise concurrent callers on its own. Measured: eight concurrent
/// redemptions of one row, up to four of them "winning".
///
/// Wrapping the statements in `BEGIN`/`COMMIT` makes a persistent datastore
/// detect the conflict and abort every loser with this error — 54% of
/// contended attempts on `surrealkv`, with zero double winners in 40 000
/// (`tools/surreal-race-probe`). That abort is the first of the two layers the
/// three single-use consume paths run since X6 (#302); the second is a nonce
/// read back after the commit, which is why the read-back lives in a query of
/// its own and this error can also surface on that second query.
///
/// For a single-use consume the abort is not a fault — it is the datastore
/// reporting that someone else got there first, which is the answer the caller
/// wanted. Callers translate it to "no row consumed"; propagating it would turn
/// a correctly-refused replay into a 500.
///
/// Matched on the message because the driver surfaces it as an opaque error
/// rather than a typed variant. Deliberately narrow: only a conflict is
/// swallowed, and only into "lost the race" — every other failure propagates.
///
/// # Why this delegates instead of holding its own markers
///
/// It used to match two literals of its own — `"failed transaction"` and
/// `"Failed to commit transaction"` — neither of which appears in the message
/// SurrealDB v3 emits for a contended write. The four callers listed above
/// therefore could not recognise the live phrasing, and answered a refused
/// replay with a 500 rather than with "no row consumed". Both literals are now
/// in [`WRITE_CONFLICT_MARKERS`] alongside the v3 phrasing, and this is a thin
/// `&E`-taking adapter over [`is_write_conflict`] so the two can never again
/// disagree about what a conflict looks like — the exact drift D-09 forbids.
pub fn is_transaction_conflict<E: std::fmt::Display>(err: &E) -> bool {
    is_write_conflict(&err.to_string())
}

pub fn take_first_or_not_found<T>(items: Vec<T>, entity: &str, id: &str) -> Result<T, DbError> {
    items.into_iter().next().ok_or_else(|| DbError::NotFound {
        entity: entity.to_string(),
        id: id.to_string(),
    })
}

// ---------------------------------------------------------------------------
// paginate — shared PaginatedResult<T> construction (QUAL-02/CQ-B10)
// ---------------------------------------------------------------------------

/// Assemble a [`PaginatedResult<T>`] from already-fetched `items`, the
/// `count_rows` from a `SELECT count() AS total ... GROUP ALL` query, and the
/// `pagination` window that was applied to the data query.
///
/// Replaces the `let total = count_rows.first().map(|r| r.total).unwrap_or(0);
/// Ok(PaginatedResult { items, total, offset, limit })` tail duplicated across
/// every repo's list method (CQ-B10).
pub fn paginate<T>(
    items: Vec<T>,
    count_rows: Vec<CountRow>,
    pagination: &Pagination,
) -> PaginatedResult<T> {
    let total = count_rows.first().map(|r| r.total).unwrap_or(0);
    PaginatedResult {
        items,
        total,
        offset: pagination.offset,
        limit: pagination.limit,
    }
}

// ---------------------------------------------------------------------------
// Free-text search
// ---------------------------------------------------------------------------

/// The SurrealQL fragment that narrows a list query to [`Pagination::search`].
///
/// Returns a clause to splice in after an existing `WHERE`, beginning with
/// ` AND ` and empty when no term was given — so a caller concatenates it
/// unconditionally and a list with no search runs exactly the query it ran
/// before this existed.
///
/// # The binding is unconditional
///
/// `$search` is always bound (to the empty string when there is no term), even
/// though the clause that reads it is then absent. The alternative — binding
/// only when the clause is present — makes every call site a branch, and a
/// caller that got the branch wrong would fail at runtime on a query variant
/// nobody runs locally. An unused binding costs nothing.
///
/// # Why `CONTAINS` and not an index
///
/// A substring match over a tenant's rows, which is what an operator typing
/// into a box means. It is not indexed, and the honest reason is that the
/// alternative — SurrealDB's full-text search — tokenises, so `01a03efd` would
/// not match `device-01_01a03efd-…` and pasting an id from a log line would
/// silently find nothing. That is the search operators actually perform. The
/// term is length-capped at deserialization (see `normalize_search`) so the
/// scan is bounded.
///
/// Both sides are lowercased: the caller's term by
/// [`Pagination::search_term`], the column by `string::lowercase` here.
///
/// # Matching the record id
///
/// `meta::id(id)` is always searched in addition to `fields`, so the id an
/// operator copied out of a log line, an audit entry or a URL finds its row
/// in the same box as a name. It is compared unlowercased — a UUID has no
/// case — via a separate disjunct.
pub fn search_clause(fields: &[&str]) -> String {
    let mut disjuncts: Vec<String> = fields
        .iter()
        .map(|f| format!("string::lowercase({f} ?? '') CONTAINS $search"))
        .collect();
    disjuncts.push("meta::id(id) CONTAINS $search".to_string());
    format!(" AND ({})", disjuncts.join(" OR "))
}

/// [`search_clause`] when `pagination` carries a term, otherwise empty.
pub fn search_filter(pagination: &Pagination, fields: &[&str]) -> String {
    if pagination.search_term().is_some() {
        search_clause(fields)
    } else {
        String::new()
    }
}

/// The value to bind to `$search` — lowercased, or empty when unsearched.
pub fn search_bind(pagination: &Pagination) -> String {
    pagination.search_term().unwrap_or_default()
}

#[cfg(test)]
mod search_tests {
    use super::*;

    fn paged(search: Option<&str>) -> Pagination {
        Pagination {
            offset: 0,
            limit: 50,
            search: search.map(str::to_string),
        }
    }

    #[test]
    fn a_whitespace_only_term_is_no_term() {
        // `normalize_search` catches this on the serde path, but a `Pagination`
        // built in code bypasses it — and `Some("   ")` would otherwise ask for
        // rows containing three spaces, returning nothing while looking like a
        // working filter.
        assert_eq!(search_filter(&paged(Some("   ")), &["name"]), "");
        assert_eq!(search_bind(&paged(Some("   "))), "");
    }

    #[test]
    fn a_term_is_trimmed_before_matching() {
        // Pasting an id out of a log line brings whitespace with it.
        assert_eq!(search_bind(&paged(Some("  Admin \n"))), "admin");
    }

    #[test]
    fn no_term_produces_no_clause() {
        // The property that keeps an unsearched list byte-identical to what it
        // was before search existed.
        assert_eq!(search_filter(&paged(None), &["username"]), "");
        assert_eq!(search_bind(&paged(None)), "");
    }

    #[test]
    fn a_term_lowercases_both_sides() {
        let clause = search_filter(&paged(Some("AdMiN")), &["username"]);
        assert!(clause.contains("string::lowercase(username ?? '')"));
        assert_eq!(search_bind(&paged(Some("AdMiN"))), "admin");
    }

    #[test]
    fn the_record_id_is_always_searchable() {
        // An operator with a UUID from a log line pastes it into the same box
        // as a name; a search that only matched names would find nothing and
        // give no hint why.
        let clause = search_filter(&paged(Some("x")), &["name"]);
        assert!(clause.contains("meta::id(id) CONTAINS $search"));
    }

    #[test]
    fn the_clause_composes_onto_an_existing_where() {
        // Spliced after `WHERE tenant_id = $tenant_id`, so it has to start with
        // ` AND ` and bracket its own disjunction — without the brackets, one
        // `OR` would escape and match rows in every tenant.
        let clause = search_filter(&paged(Some("x")), &["name", "slug"]);
        assert!(clause.starts_with(" AND ("));
        assert!(clause.ends_with(")"));
    }

    #[test]
    fn every_named_field_is_searched() {
        let clause = search_filter(&paged(Some("x")), &["username", "email"]);
        assert!(clause.contains("username"));
        assert!(clause.contains("email"));
    }
}

// ---------------------------------------------------------------------------
// Delete-target existence guard (SEC-104)
// ---------------------------------------------------------------------------

/// The sentinel a delete transaction `THROW`s when its target row does not
/// exist in the caller's tenant (SEC-104).
///
/// Not a human sentence: it is matched, not read, and a message that reads
/// like prose invites someone to reword it.
pub const DELETE_TARGET_MISSING: &str = "axiam:delete_target_missing";

/// The first statement of a delete transaction: abort unless the target row
/// exists **in this tenant** (SEC-104).
///
/// # Why the guard rather than inspecting the DELETE's result
///
/// Five repositories (`group`, `role`, `resource`, `permission`,
/// `service_account`) delete a record plus its edges inside one transaction and
/// returned `Ok(())` without looking at whether anything matched. The
/// `WHERE tenant_id = $tenant_id` predicate was — and is — correct, so no other
/// tenant's data was ever touched, and because the answer was a uniform 204 for
/// a foreign id, an unknown id and a real one, it was not an existence oracle
/// either. What it cost is an administrator who deletes the wrong id, is told
/// it worked, and believes the group is gone. `user` and `webhook` already got
/// this right with `RETURN BEFORE` + an empty-row check; this makes the other
/// five agree, in the repository, so `axiam-scim`'s hand-written pre-check can
/// be deleted rather than recopied for every future resource type.
///
/// Placing the check **inside** the transaction, as its first statement, is
/// what makes it more than a pre-check: a `THROW` aborts, so a delete against
/// a missing record leaves the edge deletes unexecuted too, rather than
/// stripping edges belonging to nothing and then reporting failure.
///
/// `table` is a literal table name from the calling repository, never caller
/// input; `$id` and `$tenant_id` are bound parameters.
pub fn delete_existence_guard(table: &str) -> String {
    format!(
        "LET $existing = (SELECT VALUE id FROM type::record('{table}', $id) \
           WHERE tenant_id = $tenant_id); \
         IF array::len($existing) == 0 {{ THROW '{DELETE_TARGET_MISSING}'; }};"
    )
}

/// Turn a delete transaction's statement errors into the right [`DbError`]
/// (SEC-104).
///
/// Scans **every** statement's error rather than trusting `Response::check()`,
/// for the reason `resource::delete` already documents: a `THROW` fires on its
/// own slot while the trailing statements report the generic "not executed due
/// to a failed transaction", and `check()` can surface one of those instead —
/// which would silently downgrade a precise `404` into an opaque `500`.
///
/// `extra` lets a repository claim a `THROW` of its own (`resource`'s
/// child-count guard) before the generic mapping runs.
pub fn map_delete_errors(
    errors: std::collections::HashMap<usize, surrealdb::Error>,
    entity: &str,
    id: &str,
) -> Result<(), DbError> {
    if errors.is_empty() {
        return Ok(());
    }
    let combined = errors
        .into_values()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("; ");
    if combined.contains(DELETE_TARGET_MISSING) {
        return Err(DbError::NotFound {
            entity: entity.to_string(),
            id: id.to_string(),
        });
    }
    Err(DbError::Migration(combined))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_uuid ---

    #[test]
    fn parse_uuid_valid_returns_ok() {
        let raw = "550e8400-e29b-41d4-a716-446655440000";
        let result = parse_uuid(raw, "user_id");
        assert!(result.is_ok(), "expected Ok for a valid UUID string");
        assert_eq!(result.unwrap().to_string(), raw);
    }

    #[test]
    fn parse_uuid_invalid_contains_field_name() {
        let err = parse_uuid("not-a-uuid", "user_id").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("user_id"),
            "error message should contain the field name; got: {msg}"
        );
    }

    #[test]
    fn parse_uuid_invalid_returns_serialization_not_migration() {
        // QUAL-03/D-10: a corrupt-data read must not be mislabeled as a
        // "Migration failed" error.
        let err = parse_uuid("not-a-uuid", "tenant_id").unwrap_err();
        match err {
            DbError::Serialization(msg) => {
                assert!(
                    msg.contains("tenant_id"),
                    "Serialization message should name the field; got: {msg}"
                );
            }
            other => panic!("expected DbError::Serialization, got {other:?}"),
        }
    }

    // --- take_first_or_not_found ---

    #[test]
    fn take_first_or_not_found_empty_returns_not_found() {
        let result: Result<i32, DbError> = take_first_or_not_found(vec![], "user", "abc");
        let err = result.unwrap_err();
        match err {
            DbError::NotFound { entity, id } => {
                assert_eq!(entity, "user");
                assert_eq!(id, "abc");
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn take_first_or_not_found_non_empty_returns_first() {
        let result: Result<i32, DbError> = take_first_or_not_found(vec![1, 2, 3], "x", "y");
        assert_eq!(result.unwrap(), 1);
    }

    // --- paginate ---

    #[test]
    fn paginate_empty_count_rows_defaults_to_zero() {
        let pagination = Pagination {
            offset: 5,
            limit: 10,
            search: None,
        };
        let result = paginate(vec![1, 2, 3], vec![], &pagination);
        assert_eq!(result.total, 0);
        assert_eq!(result.offset, 5);
        assert_eq!(result.limit, 10);
        assert_eq!(result.items, vec![1, 2, 3]);
    }

    #[test]
    fn paginate_preserves_pagination_offset_and_limit() {
        let pagination = Pagination {
            offset: 20,
            limit: 50,
            search: None,
        };
        let count_rows = vec![CountRow { total: 42 }];
        let result: PaginatedResult<i32> = paginate(vec![], count_rows, &pagination);
        assert_eq!(result.total, 42);
        assert_eq!(result.offset, 20);
        assert_eq!(result.limit, 50);
    }

    // --- DbError::AlreadyExists propagation (compile-time check via From) ---

    #[test]
    fn already_exists_converts_to_axiam_error() {
        use axiam_core::error::AxiamError;
        let db_err = DbError::AlreadyExists {
            entity: "user".to_string(),
        };
        let axiam_err: AxiamError = db_err.into();
        match axiam_err {
            AxiamError::AlreadyExists { entity } => {
                assert_eq!(entity, "user");
            }
            other => panic!("expected AxiamError::AlreadyExists, got {other:?}"),
        }
    }

    // --- classify_write_error ---

    #[test]
    fn is_write_conflict_matches_the_real_surrealdb_message() {
        // Verbatim from a SurrealDB v3 write that lost an optimistic-concurrency
        // race, captured off the wire from the `grpc_admin_validate` benchmark
        // cell (it reaches the client as the gRPC INTERNAL message).
        let msg = "Database error: Migration failed: There was a problem with the \
                   key-value store: Transaction conflict: Transaction write \
                   conflict. This transaction can be retried";
        assert!(is_write_conflict(msg));
        // A conflict is NOT a constraint violation — misfiling it as one would
        // answer a transient race with a 409.
        assert!(!is_unique_violation(msg));
    }

    #[test]
    fn is_write_conflict_matches_the_commit_time_phrasing() {
        assert!(is_write_conflict(
            "Failed to commit transaction due to a read or write conflict"
        ));
    }

    #[test]
    fn is_write_conflict_ignores_unrelated_failures() {
        // An outage must never be treated as retryable-and-then-fine.
        assert!(!is_write_conflict("There was a problem with the datastore"));
        assert!(!is_write_conflict(
            "Database index `idx_users_username_unique` already contains ['alice']"
        ));
    }

    #[test]
    fn write_conflict_backoff_grows_and_stays_bounded() {
        assert_eq!(write_conflict_backoff(1).as_millis(), 2);
        assert_eq!(write_conflict_backoff(2).as_millis(), 4);
        assert_eq!(write_conflict_backoff(3).as_millis(), 8);
        // Never a runaway shift, even if a caller passes a large attempt.
        assert_eq!(write_conflict_backoff(99).as_millis(), 64);
    }

    /// The exact message the deployed engine produced when a concurrent SCIM
    /// `PATCH /scim/v2/Users/{id}` lost its race — captured from
    /// `bench-axiam-server` during the first run of the `scim_provisioning`
    /// benchmark cell, which failed 20 of 907 operations on it.
    const LIVE_V3_CONFLICT: &str = "There was a problem with the key-value store: \
         Transaction conflict: Transaction write conflict. This transaction can be retried";

    #[test]
    fn classify_write_error_maps_a_write_conflict_to_conflict_not_migration() {
        // The regression this guards: the conflict fell through to
        // `DbError::Migration`, so a contended user write reached the operator
        // as "Migration failed: ..." — sending them after a broken schema
        // migration for a write the datastore had said to retry.
        match classify_write_error(LIVE_V3_CONFLICT, "user") {
            DbError::Conflict(msg) => assert!(msg.contains("Transaction write conflict")),
            other => panic!("expected DbError::Conflict, got {other:?}"),
        }
    }

    #[test]
    fn classify_write_error_still_prefers_a_unique_violation_over_a_conflict() {
        // Ordering matters: a UNIQUE violation is a statement about the
        // caller's request (409, and retrying reproduces it identically),
        // so it must win over the weaker, retryable conflict classification.
        let msg = "Database index `idx_users_username_unique` already contains ['alice']";
        match classify_write_error(msg, "user") {
            DbError::AlreadyExists { entity } => assert_eq!(entity, "user"),
            other => panic!("expected DbError::AlreadyExists, got {other:?}"),
        }
    }

    #[test]
    fn conflict_converts_to_a_database_error_not_a_conflict_status() {
        // Deliberate: the variant exists to stop MISLABELING, not to change the
        // client-visible contract. A 503 with Retry-After would be defensible
        // and is a separate decision.
        use axiam_core::error::AxiamError;
        let axiam_err: AxiamError = DbError::Conflict(LIVE_V3_CONFLICT.to_string()).into();
        match axiam_err {
            AxiamError::Database(msg) => assert!(msg.contains("Write conflict")),
            other => panic!("expected AxiamError::Database, got {other:?}"),
        }
    }

    #[test]
    fn is_transaction_conflict_matches_the_live_v3_message() {
        // THE BUG THIS PINS. `is_transaction_conflict` matched only
        // "failed transaction" / "Failed to commit transaction", and the
        // message SurrealDB v3 actually emits contains NEITHER. It guards the
        // single-use consume on device_grant, permission_ticket,
        // pushed_auth_request and oauth2_auth_code — so on the deployed engine
        // their "someone else got there first" branch could not fire, and a
        // correctly-refused replay surfaced as a 500 instead of "no row
        // consumed". Fail-closed, so a robustness defect rather than a hole.
        assert!(is_transaction_conflict(&LIVE_V3_CONFLICT));
    }

    #[test]
    fn is_transaction_conflict_still_matches_the_legacy_phrasings() {
        // Unifying the marker sets must not drop what the old set caught.
        assert!(is_transaction_conflict(
            &"the failed transaction was rolled back"
        ));
        assert!(is_transaction_conflict(
            &"Failed to commit transaction due to a read or write conflict"
        ));
        // And still refuses everything that is not a conflict.
        assert!(!is_transaction_conflict(&"Connection refused"));
        assert!(!is_transaction_conflict(
            &"Database index `idx_x` already contains ['a']"
        ));
    }

    #[tokio::test]
    async fn retry_on_write_conflict_retries_a_conflict_then_succeeds() {
        use std::cell::Cell;
        let calls = Cell::new(0u32);
        let out: Result<&str, DbError> = retry_on_write_conflict(|| async {
            calls.set(calls.get() + 1);
            if calls.get() < 3 {
                Err(DbError::Conflict(LIVE_V3_CONFLICT.to_string()))
            } else {
                Ok("committed")
            }
        })
        .await;
        assert_eq!(out.unwrap(), "committed");
        assert_eq!(calls.get(), 3, "should have retried twice then succeeded");
    }

    #[tokio::test]
    async fn retry_on_write_conflict_does_not_retry_anything_else() {
        // A hard failure must fail FAST — an outage turned into four slow
        // attempts is strictly worse than one quick one.
        use std::cell::Cell;
        let calls = Cell::new(0u32);
        let out: Result<(), DbError> = retry_on_write_conflict(|| async {
            calls.set(calls.get() + 1);
            Err(DbError::Migration("Connection refused".to_string()))
        })
        .await;
        assert!(matches!(out, Err(DbError::Migration(_))));
        assert_eq!(calls.get(), 1, "a non-conflict must not be retried");
    }

    #[tokio::test]
    async fn retry_on_write_conflict_is_bounded_and_surfaces_the_last_error() {
        // Sustained contention must eventually surface rather than be retried
        // forever — past a few attempts this is no longer masking a race.
        use std::cell::Cell;
        let calls = Cell::new(0u32);
        let out: Result<(), DbError> = retry_on_write_conflict(|| async {
            calls.set(calls.get() + 1);
            Err(DbError::Conflict(LIVE_V3_CONFLICT.to_string()))
        })
        .await;
        assert!(matches!(out, Err(DbError::Conflict(_))));
        assert_eq!(calls.get(), MAX_WRITE_ATTEMPTS);
    }

    #[tokio::test]
    async fn retry_on_write_conflict_recognises_a_conflict_in_any_variant() {
        // A conflict can arrive as Conflict, Surreal or Migration depending on
        // where in the write path it surfaced; the predicate reads the rendered
        // message, so every one of them must retry.
        use std::cell::Cell;
        for seed in [
            DbError::Conflict(LIVE_V3_CONFLICT.to_string()),
            DbError::Migration(LIVE_V3_CONFLICT.to_string()),
        ] {
            let rendered = seed.to_string();
            let calls = Cell::new(0u32);
            let out: Result<(), DbError> = retry_on_write_conflict(|| async {
                calls.set(calls.get() + 1);
                Err(DbError::Migration(rendered.clone()))
            })
            .await;
            assert!(out.is_err());
            assert_eq!(
                calls.get(),
                MAX_WRITE_ATTEMPTS,
                "a conflict rendered as {rendered} should have been retried"
            );
        }
    }

    #[test]
    fn classify_write_error_maps_index_violation_to_already_exists() {
        // Real SurrealDB v3 UNIQUE index violation message shape.
        let msg = "Database index `idx_users_username_unique` already contains \
                    the value ['alice'], with record `user:abc123`";
        let err = classify_write_error(msg, "user");
        match err {
            DbError::AlreadyExists { entity } => assert_eq!(entity, "user"),
            other => panic!("expected DbError::AlreadyExists, got {other:?}"),
        }
    }

    #[test]
    fn classify_write_error_passes_non_marker_error_through_as_migration() {
        // A DB outage/connection error carries none of the confirmed unique-
        // index markers and must NEVER be misclassified as a false 409.
        let msg = "There was a problem with the database: connection reset by peer";
        let err = classify_write_error(msg, "user");
        match err {
            DbError::Migration(m) => assert_eq!(m, msg),
            other => panic!("expected DbError::Migration, got {other:?}"),
        }
    }

    // --- is_unique_violation / classify_replay_write_error (F5, D-09) ---

    /// Real SurrealDB v3 UNIQUE-index violation messages, one per replay table.
    ///
    /// These are the exact shapes the three guards see. They are quoted here
    /// rather than paraphrased because the classifier is a substring match:
    /// a paraphrase that happens to contain "already contains" would pass this
    /// test while telling us nothing about the message the server sends.
    const REAL_VIOLATION_MESSAGES: [&str; 3] = [
        "Database index `idx_replay_uniq` already contains ['t1', 'assertion-1'], \
         with record `saml_assertion_replay:abc`",
        "Database index `idx_amqp_nonce_uniq` already contains ['t1', 'n-1'], \
         with record `amqp_nonce_replay:def`",
        "Database index `idx_proof_replay_uniq` already contains ['t1', 'dpop', 'jti-1'], \
         with record `oauth2_proof_replay:ghi`",
    ];

    #[test]
    fn is_unique_violation_recognises_every_real_index_message() {
        for msg in REAL_VIOLATION_MESSAGES {
            assert!(is_unique_violation(msg), "should have matched: {msg}");
        }
    }

    #[test]
    fn is_unique_violation_recognises_the_fallback_markers() {
        assert!(is_unique_violation("record already exists"));
        assert!(is_unique_violation("violates unique constraint"));
    }

    /// The safety property, stated as a test: an outage must never read as a
    /// conflict. A false "already exists" turns a 5xx into a 409, and at a
    /// replay guard a false ReplayDetected refuses legitimate traffic.
    #[test]
    fn is_unique_violation_rejects_failures_that_are_not_conflicts() {
        for msg in [
            "There was a problem with the database: connection reset by peer",
            "IO error: broken pipe",
            "There was a problem with the database: transaction timed out",
            "Serialization error: invalid UTF-8",
            "",
        ] {
            assert!(!is_unique_violation(msg), "should NOT have matched: {msg}");
        }
    }

    /// The three replay guards must agree, because they now share one
    /// definition. This test is what fails if somebody reintroduces a local
    /// copy that answers differently for one table.
    #[test]
    fn classify_replay_write_error_reports_every_real_violation_as_a_replay() {
        for msg in REAL_VIOLATION_MESSAGES {
            match classify_replay_write_error(msg) {
                AxiamError::ReplayDetected => {}
                other => panic!("expected ReplayDetected for {msg}, got {other:?}"),
            }
        }
    }

    #[test]
    fn classify_replay_write_error_passes_an_outage_through_as_database() {
        let msg = "There was a problem with the database: connection reset by peer";
        match classify_replay_write_error(msg) {
            AxiamError::Database(m) => assert_eq!(m, msg),
            other => panic!("expected AxiamError::Database, got {other:?}"),
        }
    }

    /// The three classifiers read one predicate, so they cannot disagree about
    /// whether a given message is a conflict -- only about what to call it.
    #[test]
    fn the_three_classifiers_agree_on_what_a_conflict_is() {
        for msg in REAL_VIOLATION_MESSAGES
            .iter()
            .copied()
            .chain(["connection reset by peer", "transaction timed out"])
        {
            let expected = is_unique_violation(msg);
            assert_eq!(
                matches!(classify_replay_write_error(msg), AxiamError::ReplayDetected),
                expected,
                "classify_replay_write_error disagreed on: {msg}"
            );
            assert_eq!(
                matches!(
                    classify_conflict_write_error(msg, "thing"),
                    AxiamError::AlreadyExists { .. }
                ),
                expected,
                "classify_conflict_write_error disagreed on: {msg}"
            );
            assert_eq!(
                matches!(
                    classify_write_error(msg, "thing"),
                    DbError::AlreadyExists { .. }
                ),
                expected,
                "classify_write_error disagreed on: {msg}"
            );
        }
    }

    #[test]
    fn classify_conflict_write_error_names_the_constrained_thing() {
        match classify_conflict_write_error(
            "Database index `idx_state_uniq` already contains ['s']",
            "federation_login_state.state",
        ) {
            AxiamError::AlreadyExists { entity } => {
                assert_eq!(entity, "federation_login_state.state");
            }
            other => panic!("expected AlreadyExists, got {other:?}"),
        }
    }
}

//! Shared repository utilities: common row types and helper functions
//! that were previously duplicated across every repo module.

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
    if msg.contains("already contains") || msg.contains("already exists") || msg.contains("unique")
    {
        DbError::AlreadyExists {
            entity: entity.to_string(),
        }
    } else {
        DbError::Migration(msg)
    }
}

// ---------------------------------------------------------------------------
// take_first_or_not_found — unified "0 rows → NotFound" helper
// ---------------------------------------------------------------------------

/// Take the first element of `items` or return `DbError::NotFound`.
///
/// Replaces the `into_iter().next().ok_or_else(|| DbError::NotFound{…})`
/// pattern repeated in every `get_by_id` / find method.
pub fn take_first_or_not_found<T>(items: Vec<T>, entity: &str, id: &str) -> Result<T, DbError> {
    items.into_iter().next().ok_or_else(|| DbError::NotFound {
        entity: entity.to_string(),
        id: id.to_string(),
    })
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
}

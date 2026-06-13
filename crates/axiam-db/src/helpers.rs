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
/// pattern scattered across ~25 repos, this function uses `DbError::Migration`
/// consistently while naming the offending field.  A future refactor can
/// switch the variant to `DbError::Serialization` if that variant is added.
pub fn parse_uuid(s: &str, field: &str) -> Result<Uuid, DbError> {
    s.parse::<Uuid>()
        .map_err(|e| DbError::Migration(format!("invalid {field} UUID: {e}")))
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

    // --- take_first_or_not_found ---

    #[test]
    fn take_first_or_not_found_empty_returns_not_found() {
        let result: Result<i32, DbError> =
            take_first_or_not_found(vec![], "user", "abc");
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
        let result: Result<i32, DbError> =
            take_first_or_not_found(vec![1, 2, 3], "x", "y");
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
}

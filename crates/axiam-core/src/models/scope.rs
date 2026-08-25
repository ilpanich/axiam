//! Scope domain model.
//!
//! Scopes define fine-grained sub-resource permissions within a resource.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Scope {
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// The resource this scope belongs to.
    pub resource_id: Uuid,
    pub name: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateScope {
    pub tenant_id: Uuid,
    pub resource_id: Uuid,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct UpdateScope {
    pub name: Option<String>,
    pub description: Option<String>,
}

/// The name of the scope every new resource is given.
///
/// A resource with no scopes at all is a resource whose permission grants can
/// only ever be all-or-nothing: the "limit to scopes" picker in the admin UI
/// shows an empty list, and the operator has to go and invent a scope before
/// they can narrow anything. Seeding one named after the resource means a fresh
/// resource is immediately usable in a scoped grant, and it names the thing it
/// covers.
///
/// The rule is the resource's own name with spaces replaced by hyphens. Runs of
/// whitespace collapse to a single hyphen and the ends are trimmed, so
/// `"  Billing   Reports "` yields `"Billing-Reports"` rather than
/// `"--Billing---Reports-"` — a scope name is typed into policy and pasted into
/// SDK calls, and a doubled hyphen from an accidental double space is a
/// footgun nobody would choose deliberately.
///
/// Case is left alone. Lowercasing would be a second, unasked-for
/// transformation, and `Billing-Reports` is what an operator who typed
/// `Billing Reports` expects to see.
///
/// Returns `None` when the name has no non-whitespace content, because there is
/// no scope name to build — the caller creates no default scope in that case
/// rather than one called `""`.
///
/// # Examples
///
/// ```
/// use axiam_core::models::scope::default_scope_name;
///
/// assert_eq!(default_scope_name("Billing"), Some("Billing".to_string()));
/// assert_eq!(
///     default_scope_name("Billing Reports"),
///     Some("Billing-Reports".to_string())
/// );
/// // Whitespace runs collapse; the ends are trimmed.
/// assert_eq!(
///     default_scope_name("  Billing   Reports "),
///     Some("Billing-Reports".to_string())
/// );
/// // Tabs and newlines are whitespace too.
/// assert_eq!(
///     default_scope_name("Billing\treports"),
///     Some("Billing-reports".to_string())
/// );
/// // Nothing to name.
/// assert_eq!(default_scope_name("   "), None);
/// ```
pub fn default_scope_name(resource_name: &str) -> Option<String> {
    let name = resource_name
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("-");
    if name.is_empty() { None } else { Some(name) }
}

/// The description given to the scope [`default_scope_name`] names.
///
/// Says where it came from, so an operator who did not expect a scope to exist
/// can tell it was seeded rather than typed by a colleague — and knows it is
/// safe to rename or delete.
pub fn default_scope_description(resource_name: &str) -> String {
    format!("Default scope for the \"{resource_name}\" resource.")
}

#[cfg(test)]
mod default_scope_tests {
    use super::*;

    #[test]
    fn a_single_word_name_is_unchanged() {
        assert_eq!(default_scope_name("Billing"), Some("Billing".into()));
    }

    #[test]
    fn spaces_become_hyphens() {
        assert_eq!(
            default_scope_name("Customer Billing Reports"),
            Some("Customer-Billing-Reports".into())
        );
    }

    #[test]
    fn runs_of_whitespace_collapse_to_one_hyphen() {
        // The alternative — a naive `replace(' ', "-")` — turns a double space
        // into `--`, which then has to be typed exactly that way in every policy
        // that references the scope.
        assert_eq!(
            default_scope_name("Billing   Reports"),
            Some("Billing-Reports".into())
        );
    }

    #[test]
    fn leading_and_trailing_whitespace_is_trimmed() {
        assert_eq!(
            default_scope_name("  Billing Reports  "),
            Some("Billing-Reports".into())
        );
    }

    #[test]
    fn tabs_and_newlines_count_as_whitespace() {
        assert_eq!(
            default_scope_name("Billing\tReports\nQ1"),
            Some("Billing-Reports-Q1".into())
        );
    }

    #[test]
    fn case_is_preserved() {
        // Lowercasing would be a transformation nobody asked for, and the
        // operator who typed `Billing Reports` expects to recognise the result.
        assert_eq!(
            default_scope_name("Billing REPORTS"),
            Some("Billing-REPORTS".into())
        );
    }

    #[test]
    fn existing_hyphens_survive() {
        assert_eq!(
            default_scope_name("Multi-Region Billing"),
            Some("Multi-Region-Billing".into())
        );
    }

    #[test]
    fn a_blank_name_yields_no_scope() {
        assert_eq!(default_scope_name(""), None);
        assert_eq!(default_scope_name("   "), None);
        assert_eq!(default_scope_name("\t\n"), None);
    }

    #[test]
    fn the_description_names_the_resource_it_came_from() {
        let d = default_scope_description("Billing Reports");
        assert!(d.contains("Billing Reports"));
    }
}

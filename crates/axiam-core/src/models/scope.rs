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
/// The rule is the resource's own name with whitespace replaced by hyphens,
/// then an underscore and the resource's id: `"device 01"` on resource
/// `01a03efd-…` becomes `"device-01_01a03efd-024c-7433-9c59-46cbc3a940fa"`.
///
/// Runs of whitespace collapse to a single hyphen and the ends are trimmed, so
/// `"  Billing   Reports "` yields `"Billing-Reports_<id>"` rather than
/// `"--Billing---Reports-_<id>"` — a scope name is typed into policy and pasted
/// into SDK calls, and a doubled hyphen from an accidental double space is a
/// footgun nobody would choose deliberately.
///
/// Case is left alone. Lowercasing would be a second, unasked-for
/// transformation, and `Billing-Reports` is what an operator who typed
/// `Billing Reports` expects to see.
///
/// # Why the id is in the name
///
/// Scope names are unique per resource, not per tenant, so the bare name was
/// never *invalid* — but two resources called `Billing Reports` in different
/// parts of the hierarchy both seeded a scope called `Billing-Reports`, and
/// from then on every grant, policy line and SDK call naming that scope read
/// identically while meaning different things. An operator reviewing a role
/// could not tell which resource a scoped grant narrowed to without resolving
/// the resource id by hand.
///
/// Appending the id makes the seeded name unique across the whole deployment
/// and self-describing: the resource it belongs to is readable straight off
/// the scope. The separator is an underscore precisely because the name half
/// uses hyphens and a UUID contains them — `_` is the one character that
/// still splits the two halves unambiguously.
///
/// The cost is a longer name, which is the right trade for a seeded default:
/// it is generated, not typed, and an operator who wants a short name renames
/// it. A name that is short and ambiguous cannot be fixed after the fact,
/// because by then policy refers to it.
///
/// Returns `None` when the name has no non-whitespace content, because there is
/// no scope name to build — the caller creates no default scope in that case
/// rather than one called `"_<id>"`.
///
/// # Examples
///
/// ```
/// use axiam_core::models::scope::default_scope_name;
/// use uuid::Uuid;
///
/// let id = Uuid::parse_str("01a03efd-024c-7433-9c59-46cbc3a940fa").unwrap();
///
/// assert_eq!(
///     default_scope_name("device 01", id),
///     Some("device-01_01a03efd-024c-7433-9c59-46cbc3a940fa".to_string())
/// );
/// // Whitespace runs collapse; the ends are trimmed.
/// assert_eq!(
///     default_scope_name("  Billing   Reports ", id),
///     Some("Billing-Reports_01a03efd-024c-7433-9c59-46cbc3a940fa".to_string())
/// );
/// // Nothing to name.
/// assert_eq!(default_scope_name("   ", id), None);
/// ```
pub fn default_scope_name(resource_name: &str, resource_id: uuid::Uuid) -> Option<String> {
    let name = resource_name
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("-");
    if name.is_empty() {
        None
    } else {
        Some(format!("{name}_{resource_id}"))
    }
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

    /// A fixed id so every expectation below reads as one literal string.
    const ID: &str = "01a03efd-024c-7433-9c59-46cbc3a940fa";

    fn id() -> Uuid {
        Uuid::parse_str(ID).unwrap()
    }

    fn name(resource_name: &str) -> Option<String> {
        default_scope_name(resource_name, id())
    }

    #[test]
    fn a_single_word_name_keeps_its_word_and_gains_the_id() {
        assert_eq!(name("Billing"), Some(format!("Billing_{ID}")));
    }

    #[test]
    fn spaces_become_hyphens() {
        assert_eq!(
            name("Customer Billing Reports"),
            Some(format!("Customer-Billing-Reports_{ID}"))
        );
    }

    #[test]
    fn runs_of_whitespace_collapse_to_one_hyphen() {
        // The alternative — a naive `replace(' ', "-")` — turns a double space
        // into `--`, which then has to be typed exactly that way in every policy
        // that references the scope.
        assert_eq!(
            name("Billing   Reports"),
            Some(format!("Billing-Reports_{ID}"))
        );
    }

    #[test]
    fn leading_and_trailing_whitespace_is_trimmed() {
        assert_eq!(
            name("  Billing Reports  "),
            Some(format!("Billing-Reports_{ID}"))
        );
    }

    #[test]
    fn tabs_and_newlines_count_as_whitespace() {
        assert_eq!(
            name("Billing\tReports\nQ1"),
            Some(format!("Billing-Reports-Q1_{ID}"))
        );
    }

    #[test]
    fn case_is_preserved() {
        // Lowercasing would be a transformation nobody asked for, and the
        // operator who typed `Billing Reports` expects to recognise the result.
        assert_eq!(
            name("Billing REPORTS"),
            Some(format!("Billing-REPORTS_{ID}"))
        );
    }

    #[test]
    fn existing_hyphens_survive() {
        assert_eq!(
            name("Multi-Region Billing"),
            Some(format!("Multi-Region-Billing_{ID}"))
        );
    }

    #[test]
    fn a_blank_name_yields_no_scope() {
        // Not `"_<id>"`: a scope whose whole name is a separator and an id
        // tells an operator nothing, and the caller is better off seeding none.
        assert_eq!(name(""), None);
        assert_eq!(name("   "), None);
        assert_eq!(name("\t\n"), None);
    }

    /// The property the id is there for.
    #[test]
    fn same_name_on_two_resources_yields_two_distinct_scopes() {
        let a = default_scope_name("Billing Reports", Uuid::new_v4()).unwrap();
        let b = default_scope_name("Billing Reports", Uuid::new_v4()).unwrap();
        assert_ne!(
            a, b,
            "two resources sharing a name must not seed scopes sharing a name — \
             every grant naming one would otherwise read identically while \
             narrowing to a different resource"
        );
        assert!(a.starts_with("Billing-Reports_") && b.starts_with("Billing-Reports_"));
    }

    /// The separator has to survive the name half, which uses hyphens, and the
    /// id half, which contains them.
    #[test]
    fn the_id_is_recoverable_from_the_scope_name() {
        let n = name("Multi-Region Billing").unwrap();
        let (prefix, suffix) = n
            .rsplit_once('_')
            .expect("an underscore separates the halves");
        assert_eq!(prefix, "Multi-Region-Billing");
        assert_eq!(Uuid::parse_str(suffix).unwrap(), id());
    }

    #[test]
    fn the_description_names_the_resource_it_came_from() {
        let d = default_scope_description("Billing Reports");
        assert!(d.contains("Billing Reports"));
    }
}

//! Permission domain model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Permission {
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// The action this permission represents (e.g., `read`, `write`, `delete`).
    pub action: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreatePermission {
    pub tenant_id: Uuid,
    pub action: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct UpdatePermission {
    pub action: Option<String>,
    pub description: Option<String>,
}

/// Whether a grant permits an action or refuses it (B1, deny-override).
///
/// # Precedence
///
/// Default deny -> an [`PermissionEffect::Allow`] grant permits ->
/// a [`PermissionEffect::Deny`] grant refuses, **and beats every allow**,
/// wherever either sits in the resource hierarchy. Deny wins; there is no
/// most-specific-wins tie-break.
///
/// That choice is deliberate and is argued in full in
/// `claude_dev/deny-override-design.md` §2.1. The short version: deny-override
/// buys one checkable property — **adding a deny rule can never widen access,
/// and can never be undone by adding allows** — and most-specific-wins buys
/// expressiveness at the cost of making "is X denied?" unanswerable without
/// enumerating every other rule that might out-specify it.
///
/// [`PermissionEffect::Allow`] is the default, so data written before this
/// existed, and clients that send no `effect`, both mean "allow". No migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum PermissionEffect {
    /// Permits the action (the default, and the pre-B1 behaviour).
    #[default]
    Allow,
    /// Refuses the action, overriding any allow.
    Deny,
}

impl PermissionEffect {
    /// Stable, log-safe and wire-safe name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }

    /// Parse a wire value. Unknown values map to `None` so a caller can reject
    /// them rather than silently defaulting — a typo'd `"denyy"` must not
    /// become an allow.
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }

    /// Whether this effect refuses the action.
    pub const fn is_deny(self) -> bool {
        matches!(self, Self::Deny)
    }
}

/// A permission grant with optional scope constraints.
/// Empty `scope_ids` means the grant covers all scopes (wildcard).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PermissionGrant {
    pub permission: Permission,
    pub scope_ids: Vec<Uuid>,
    /// B1: whether this grant permits or refuses. Defaults to
    /// [`PermissionEffect::Allow`], which is what every pre-B1 row and every
    /// `effect`-less request means.
    ///
    /// Scope interaction: an empty `scope_ids` is a **wildcard**, so a deny
    /// with no scopes masks the action entirely on this node and its
    /// descendants — every scope, and unscoped checks too. A scoped deny masks
    /// only the scopes it names.
    #[serde(default)]
    pub effect: PermissionEffect,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_is_the_default_so_pre_b1_rows_and_effectless_requests_mean_allow() {
        // The no-migration property: absent `effect` must read as allow. If
        // this ever flipped, every existing grant would silently become a deny
        // and the whole authorization model would invert.
        assert_eq!(PermissionEffect::default(), PermissionEffect::Allow);
        let grant: PermissionEffect = serde_json::from_str("\"allow\"").unwrap();
        assert_eq!(grant, PermissionEffect::Allow);
    }

    #[test]
    fn wire_names_round_trip_through_serde_and_as_str() {
        for effect in [PermissionEffect::Allow, PermissionEffect::Deny] {
            let json = serde_json::to_string(&effect).unwrap();
            assert_eq!(json, format!("\"{}\"", effect.as_str()));
            let back: PermissionEffect = serde_json::from_str(&json).unwrap();
            assert_eq!(back, effect);
        }
    }

    #[test]
    fn from_wire_accepts_case_and_whitespace_variation() {
        assert_eq!(
            PermissionEffect::from_wire("deny"),
            Some(PermissionEffect::Deny)
        );
        assert_eq!(
            PermissionEffect::from_wire("  DENY "),
            Some(PermissionEffect::Deny)
        );
        assert_eq!(
            PermissionEffect::from_wire("Allow"),
            Some(PermissionEffect::Allow)
        );
    }

    #[test]
    fn from_wire_refuses_anything_it_does_not_recognise() {
        // The security-relevant half. A typo must NOT fall back to allow:
        // `denyy` becoming an allow is how a deny rule silently stops working.
        for raw in ["denyy", "DENY!", "", "permit", "true", "0"] {
            assert_eq!(
                PermissionEffect::from_wire(raw),
                None,
                "{raw:?} must not parse"
            );
        }
    }

    #[test]
    fn is_deny_answers_only_for_deny() {
        assert!(PermissionEffect::Deny.is_deny());
        assert!(!PermissionEffect::Allow.is_deny());
    }

    #[test]
    fn a_grant_without_an_effect_field_deserializes_as_allow() {
        // `PermissionGrant.effect` carries `#[serde(default)]` for exactly the
        // rows written before B1. Asserting on the struct, not just the enum,
        // because the default lives on the field.
        let json = serde_json::json!({
            "permission": {
                "id": Uuid::nil(),
                "tenant_id": Uuid::nil(),
                "action": "read",
                "description": "",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z"
            },
            "scope_ids": []
        });
        let grant: PermissionGrant = serde_json::from_value(json).unwrap();
        assert_eq!(grant.effect, PermissionEffect::Allow);
        assert!(
            grant.scope_ids.is_empty(),
            "empty scope_ids is the wildcard"
        );
    }
}

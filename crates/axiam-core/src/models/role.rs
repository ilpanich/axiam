//! Role domain model.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Role {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: String,
    /// Global roles grant permissions across all resources.
    pub is_global: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateRole {
    pub tenant_id: Uuid,
    pub name: String,
    pub description: String,
    pub is_global: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct UpdateRole {
    pub name: Option<String>,
    pub description: Option<String>,
    pub is_global: Option<bool>,
}

/// Which tenants an assignment reaches, on top of the resource it is scoped to.
///
/// # What this adds, and why it is not a resource scope
///
/// A role assignment already answers *which resources* it covers. It did not
/// answer *which tenants*, because until organization scope existed there was
/// only ever one: the tenant the role lives in.
///
/// An organization-level principal broke that. Its roles live in the
/// organization's reserved tenant and its global assignments deliberately
/// carry into **every** tenant of the organization — which is right for an
/// organization administrator and wrong for the case this exists to serve: an
/// organization-level account that should administer two of the organization's
/// twelve tenants and no others.
///
/// A resource scope cannot express that. Resources live *inside* a tenant, and
/// a resource id from the organization tenant names nothing in a child tenant —
/// `axiam_authz` says so explicitly when it drops resource-scoped assignments
/// at a tenant boundary. Tenant reach is a different axis, so it is a different
/// field.
///
/// # Semantics
///
/// * `None` — the assignment reaches wherever the role does. In an ordinary
///   tenant that is that tenant; in an organization scope tenant it is every
///   tenant of the organization. This is what every assignment written before
///   this field existed means, and it is what an unspecified scope keeps
///   meaning.
/// * `Some(tenants)` — the assignment contributes **only** while acting on a
///   tenant in the list, and nowhere else. That "nowhere else" includes the
///   organization's own scope: an account restricted to tenants A and B is not
///   an organization-wide administrator, and letting its grants apply while no
///   tenant is selected would hand it back the organization-level reach the
///   restriction exists to remove.
/// * `Some([])` is not a meaningful restriction (it would reach nothing at all)
///   and the API refuses it rather than writing an assignment that can never
///   apply.
pub type TenantScope = Option<Vec<Uuid>>;

/// Whether an assignment carrying `tenant_scope` applies while acting on
/// `tenant_id`.
///
/// The single rule the whole feature rests on, written once so the authorization
/// engine, `/auth/me` and the tenant listing cannot drift apart on it.
#[must_use]
pub fn tenant_scope_reaches(tenant_scope: &TenantScope, tenant_id: Uuid) -> bool {
    match tenant_scope {
        None => true,
        Some(tenants) => tenants.contains(&tenant_id),
    }
}

/// The scope of a new role assignment: the resource it covers, and the tenants
/// it reaches.
///
/// One struct rather than two positional `Option`s on every `assign_*` method:
/// `Option<Uuid>` and `Option<Vec<Uuid>>` sitting next to each other in a call
/// are two arguments nobody can read at the call site, and the two mean
/// genuinely different things.
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AssignmentScope {
    /// `None` assigns the role globally — every resource in reach.
    pub resource_id: Option<Uuid>,
    /// `None` reaches wherever the role does. See [`TenantScope`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_scope: Option<Vec<Uuid>>,
}

impl AssignmentScope {
    /// A global, unrestricted assignment — what every assignment was before
    /// either field existed.
    #[must_use]
    pub fn global() -> Self {
        Self::default()
    }

    /// Scoped to one resource, reaching wherever the role does.
    #[must_use]
    pub fn resource(resource_id: Uuid) -> Self {
        Self {
            resource_id: Some(resource_id),
            tenant_scope: None,
        }
    }
}

/// The resource scope on its own, which is what every caller passed before
/// tenant reach existed and what most of them still mean.
impl From<Option<Uuid>> for AssignmentScope {
    fn from(resource_id: Option<Uuid>) -> Self {
        Self {
            resource_id,
            tenant_scope: None,
        }
    }
}

/// A role together with its assignment context (the resource it is scoped to).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RoleAssignment {
    pub role: Role,
    /// `None` means the role was assigned globally (no resource scope).
    pub resource_id: Option<Uuid>,
    /// The tenants this assignment reaches. See [`TenantScope`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_scope: Option<Vec<Uuid>>,
}

impl RoleAssignment {
    /// Whether this assignment contributes anything while acting on
    /// `tenant_id`.
    #[must_use]
    pub fn reaches_tenant(&self, tenant_id: Uuid) -> bool {
        tenant_scope_reaches(&self.tenant_scope, tenant_id)
    }
}

/// One `has_role` edge seen from the *role's* side: which subject holds the
/// assignment, and the resource it is scoped to.
///
/// `has_role` carries a `UNIQUE(in, out)` index, so a subject holds a given
/// role at most once — this is one row per subject, same as listing subject
/// ids. What it adds is `resource_id`, and that field is not decoration: an
/// unassign that does not name it deletes the edge whose `resource_id` is
/// `NONE`, so revoking a resource-scoped grant without it silently deletes
/// nothing.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RoleSubjectAssignment {
    /// The user or group holding the assignment.
    pub subject_id: Uuid,
    /// `None` means the role was assigned globally (no resource scope).
    pub resource_id: Option<Uuid>,
    /// The tenants this assignment reaches. See [`TenantScope`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_scope: Option<Vec<Uuid>>,
}

/// How far across an organization's tenants a principal's assignments reach.
///
/// Derived from the whole set of a principal's assignments, because reach is a
/// property of the set and not of any one of them: holding *one* unrestricted
/// assignment makes the principal unrestricted however many tenant-scoped ones
/// sit beside it — those add tenants, they cannot take any away.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantReach {
    /// Wherever the roles themselves reach. For a principal in an
    /// organization's scope tenant that is every tenant of the organization;
    /// for an ordinary principal it is the one tenant it lives in.
    Unrestricted,
    /// Only these tenants. Possibly empty, which is a principal that can act
    /// nowhere — the assign API refuses to create one, but a set can shrink to
    /// empty afterwards by deleting the tenants an assignment named.
    Restricted(BTreeSet<Uuid>),
}

impl TenantReach {
    /// Whether acting on `tenant_id` is within reach.
    #[must_use]
    pub fn includes(&self, tenant_id: Uuid) -> bool {
        match self {
            Self::Unrestricted => true,
            Self::Restricted(tenants) => tenants.contains(&tenant_id),
        }
    }

    /// Whether this reach is narrower than the organization it sits in.
    ///
    /// The question organization-level *actions* ask: creating a tenant or
    /// minting the organization's CA is an act on the organization as a whole,
    /// and a principal deliberately confined to some of its tenants is not
    /// entitled to it.
    #[must_use]
    pub fn is_restricted(&self) -> bool {
        matches!(self, Self::Restricted(_))
    }
}

/// The reach of a principal holding `assignments`.
///
/// One unrestricted assignment is enough — see [`TenantReach`].
///
/// # An empty set is unrestricted, not restricted-to-nothing
///
/// A principal with no assignments has no grants to bound, so there is nothing
/// for a reach to describe. Reporting [`TenantReach::Restricted`] with an empty
/// set would be arithmetically tidy and wrong in use: callers ask
/// `is_restricted()` to mean *"this account was deliberately confined"*, and a
/// principal that simply holds no roles was not. It would then be refused
/// organization-level actions with "your roles are restricted to particular
/// tenants", which names the wrong reason — and the permission check refuses it
/// anyway, on the right one.
#[must_use]
pub fn tenant_reach_of(assignments: &[RoleAssignment]) -> TenantReach {
    if assignments.is_empty() {
        return TenantReach::Unrestricted;
    }
    let mut tenants = BTreeSet::new();
    for assignment in assignments {
        match &assignment.tenant_scope {
            None => return TenantReach::Unrestricted,
            Some(scope) => tenants.extend(scope.iter().copied()),
        }
    }
    TenantReach::Restricted(tenants)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assignment(tenant_scope: Option<Vec<Uuid>>) -> RoleAssignment {
        let now = Utc::now();
        RoleAssignment {
            role: Role {
                id: Uuid::new_v4(),
                tenant_id: Uuid::new_v4(),
                name: "r".into(),
                description: String::new(),
                is_global: true,
                created_at: now,
                updated_at: now,
            },
            resource_id: None,
            tenant_scope,
        }
    }

    #[test]
    fn no_assignments_is_unrestricted_not_confined_to_nothing() {
        // The distinction the guard rests on: "holds no roles" and "was
        // deliberately confined" are different facts, and only the second one
        // should produce "your roles are restricted to particular tenants".
        assert_eq!(tenant_reach_of(&[]), TenantReach::Unrestricted);
    }

    #[test]
    fn one_unrestricted_assignment_makes_the_whole_set_unrestricted() {
        let tenant = Uuid::new_v4();
        let reach = tenant_reach_of(&[assignment(Some(vec![tenant])), assignment(None)]);
        assert_eq!(reach, TenantReach::Unrestricted);
        assert!(!reach.is_restricted());
    }

    #[test]
    fn scoped_assignments_union_their_tenants() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let reach = tenant_reach_of(&[assignment(Some(vec![a])), assignment(Some(vec![b]))]);
        assert!(reach.is_restricted());
        assert!(reach.includes(a));
        assert!(reach.includes(b));
        assert!(!reach.includes(Uuid::new_v4()));
    }

    #[test]
    fn an_assignment_reaches_only_the_tenants_it_names() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        assert!(assignment(None).reaches_tenant(a));
        assert!(assignment(Some(vec![a])).reaches_tenant(a));
        assert!(!assignment(Some(vec![a])).reaches_tenant(b));
        // An empty list reaches nothing. The API refuses to create one; if a
        // row ever holds one it must not read back as "everywhere".
        assert!(!assignment(Some(vec![])).reaches_tenant(a));
    }
}

//! Public types for the authorization engine.

use uuid::Uuid;

/// The result of an authorization check.
///
/// # Why deny has two shapes (B1)
///
/// `Deny` and `DeniedByRule` are both refusals and both become a 403. They are
/// distinguished because they mean opposite things to the person who hit them:
///
/// - `Deny` — nothing granted this. **Ask an admin for access.**
/// - `DeniedByRule` — an explicit deny rule matched. **An admin has already
///   decided.**
///
/// Collapsing the two into a bare `false`, which is what a client does without
/// this distinction, throws away the only information that tells a user which
/// of those two situations they are in. SDK contract §11 requires helpers to
/// surface the reason rather than flatten it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessDecision {
    /// A grant matched and no explicit deny overrode it.
    Allow,
    /// Default deny — no grant matched.
    Deny(String),
    /// An explicit deny grant matched and overrode any allow (B1).
    DeniedByRule(String),
}

impl AccessDecision {
    /// Whether this decision permits the request.
    ///
    /// The only place a caller should collapse a decision to a boolean. Both
    /// refusals answer `false` here, which is correct at an enforcement point
    /// and lossy anywhere a human will read the result -- see the type's own
    /// documentation for why the two are distinguished at all.
    pub fn is_allowed(&self) -> bool {
        matches!(self, AccessDecision::Allow)
    }

    /// Whether this refusal came from an explicit deny rule rather than from
    /// the absence of a grant.
    pub fn is_denied_by_rule(&self) -> bool {
        matches!(self, AccessDecision::DeniedByRule(_))
    }

    /// The stable machine-readable reason code carried on the wire
    /// (`allowed` | `no_grant` | `denied_by_rule`) — SDK contract §11.
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::Allow => "allowed",
            Self::Deny(_) => "no_grant",
            Self::DeniedByRule(_) => "denied_by_rule",
        }
    }

    /// The human-readable reason, empty for an allow.
    pub fn reason(&self) -> &str {
        match self {
            Self::Allow => "",
            Self::Deny(r) | Self::DeniedByRule(r) => r,
        }
    }
}

/// Input for an authorization check.
#[derive(Debug, Clone)]
pub struct AccessRequest {
    /// The tenant the check is scoped to — the tenant being **acted upon**.
    /// Resources, scopes and their hierarchy are resolved here, so a request
    /// can never see another tenant's resources.
    pub tenant_id: Uuid,
    /// Where the subject's grants live, and whether they reach beyond
    /// [`Self::tenant_id`].
    ///
    /// See [`SubjectScope`]. Defaults to [`SubjectScope::Tenant`], which is
    /// every ordinary principal and is exactly the behaviour that existed
    /// before organization scope.
    pub subject_scope: SubjectScope,
    /// Who is asking -- a user id, or a service account's id. The engine
    /// resolves roles by subject id, directly and through group membership.
    pub subject_id: Uuid,
    /// What they want to do, as a `resource:verb` permission name
    /// (`"users:create"`).
    pub action: String,
    /// What they want to do it to. The nil UUID is the "global" sentinel,
    /// meaning a permission not attached to any particular resource; anything
    /// else is a resource whose ancestors are walked for inherited grants.
    pub resource_id: Uuid,
    /// Optional scope for sub-resource granularity.
    pub scope: Option<String>,
}

/// Whose grants answer for a subject, and how far they reach.
///
/// # Why this is an enum and not an `Option<Uuid>`
///
/// It was an `Option<Uuid>` first — "the tenant the subject's grants live in,
/// when that is not the tenant being acted upon" — and that encoding is unsafe
/// in a way that took a test to notice. Two ids that merely *differ* is not the
/// same claim as "this principal operates organization-wide", but it reads like
/// it: any caller that built a request for a subject in tenant A about tenant B
/// got cross-tenant reach for free, because differing was the whole condition.
/// A tenant user's ordinary global role — `admin`, say — then applied in every
/// tenant in the deployment, which is the exact opposite of what a tenant is.
///
/// Naming the claim fixes that. [`Self::Organization`] is a statement about the
/// *principal*, and a caller has to make it deliberately; there is no
/// combination of ordinary values that produces it by accident.
///
/// # The invariant, and who keeps it
///
/// [`Self::Organization`] must only ever be constructed for a principal whose
/// home tenant really is the organization's reserved scope. The REST extractor
/// is the sole production producer, and it resolves the tenant record and
/// checks `kind` before making the claim — never from request input, since a
/// caller that could assert its own scope could assert anyone's grants as its
/// own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SubjectScope {
    /// The subject's grants live in the tenant being acted upon, and reach no
    /// further. Every ordinary user and service account.
    #[default]
    Tenant,
    /// The subject is **organization-level**: its user row, roles and group
    /// memberships live in the organization's reserved tenant, named here,
    /// while the resource it is reaching for may be in any tenant of that
    /// organization.
    ///
    /// Crossing that boundary narrows what carries: only **global** grants
    /// apply. A resource-scoped assignment names a resource in the organization
    /// tenant and says nothing about a same-named resource elsewhere;
    /// honouring it across the boundary would be a silent escalation between
    /// isolated tenants.
    Organization {
        /// The organization's reserved tenant, where the grants are.
        tenant_id: Uuid,
    },
}

impl AccessRequest {
    /// The tenant whose role assignments answer for this subject.
    pub fn assignment_tenant_id(&self) -> Uuid {
        match self.subject_scope {
            SubjectScope::Tenant => self.tenant_id,
            SubjectScope::Organization { tenant_id } => tenant_id,
        }
    }

    /// Whether the subject's grants are being read across a tenant boundary.
    ///
    /// True only for an organization-level principal acting on a tenant that is
    /// not its own. When true, the engine keeps only global grants — the one
    /// rule organization scope adds to RBAC.
    ///
    /// An organization-level principal acting on the organization tenant itself
    /// is *not* crossing anything, and gets ordinary resource-scoped evaluation
    /// there.
    pub fn crosses_tenant_boundary(&self) -> bool {
        self.assignment_tenant_id() != self.tenant_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request(scope: Option<&str>) -> AccessRequest {
        AccessRequest {
            tenant_id: Uuid::new_v4(),
            subject_id: Uuid::new_v4(),
            action: "read".to_string(),
            resource_id: Uuid::new_v4(),
            scope: scope.map(|s| s.to_string()),
        }
    }

    #[test]
    fn is_allowed_true_for_allow() {
        assert!(AccessDecision::Allow.is_allowed());
    }

    #[test]
    fn is_allowed_false_for_deny() {
        let decision = AccessDecision::Deny("no permission grants action 'read'".to_string());
        assert!(!decision.is_allowed());
    }

    #[test]
    fn access_decision_equality_allow() {
        assert_eq!(AccessDecision::Allow, AccessDecision::Allow);
    }

    #[test]
    fn access_decision_equality_deny_same_reason() {
        let a = AccessDecision::Deny("nope".to_string());
        let b = AccessDecision::Deny("nope".to_string());
        assert_eq!(a, b);
    }

    #[test]
    fn access_decision_inequality_deny_different_reason() {
        let a = AccessDecision::Deny("nope".to_string());
        let b = AccessDecision::Deny("also nope".to_string());
        assert_ne!(a, b);
    }

    #[test]
    fn access_decision_inequality_allow_vs_deny() {
        let allow = AccessDecision::Allow;
        let deny = AccessDecision::Deny("nope".to_string());
        assert_ne!(allow, deny);
    }

    #[test]
    fn access_decision_debug_format_allow() {
        assert_eq!(format!("{:?}", AccessDecision::Allow), "Allow");
    }

    #[test]
    fn access_decision_debug_format_deny() {
        let decision = AccessDecision::Deny("reason".to_string());
        assert_eq!(format!("{:?}", decision), "Deny(\"reason\")");
    }

    #[test]
    fn access_decision_clone_round_trip() {
        let original = AccessDecision::Deny("cloned".to_string());
        let cloned = original.clone();
        assert_eq!(original, cloned);
        assert!(!cloned.is_allowed());
    }

    #[test]
    fn access_request_without_scope() {
        let req = sample_request(None);
        assert!(req.scope.is_none());
        assert_eq!(req.action, "read");
    }

    #[test]
    fn access_request_with_scope() {
        let req = sample_request(Some("sub-resource"));
        assert_eq!(req.scope.as_deref(), Some("sub-resource"));
    }

    #[test]
    fn access_request_clone_round_trip() {
        let req = sample_request(Some("scope-a"));
        let cloned = req.clone();
        assert_eq!(cloned.tenant_id, req.tenant_id);
        assert_eq!(cloned.subject_id, req.subject_id);
        assert_eq!(cloned.action, req.action);
        assert_eq!(cloned.resource_id, req.resource_id);
        assert_eq!(cloned.scope, req.scope);
    }

    #[test]
    fn access_request_debug_contains_action() {
        let req = sample_request(None);
        let debug = format!("{:?}", req);
        assert!(debug.contains("read"));
    }
}

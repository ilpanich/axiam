//! Public types for the authorization engine.

use uuid::Uuid;

/// The result of an authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessDecision {
    Allow,
    Deny(String),
}

impl AccessDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, AccessDecision::Allow)
    }
}

/// Input for an authorization check.
#[derive(Debug, Clone)]
pub struct AccessRequest {
    pub tenant_id: Uuid,
    pub subject_id: Uuid,
    pub action: String,
    pub resource_id: Uuid,
    /// Optional scope for sub-resource granularity.
    pub scope: Option<String>,
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

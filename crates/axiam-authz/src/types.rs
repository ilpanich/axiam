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

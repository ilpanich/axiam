//! The deployment profile (G-8, D-59): whether this process runs with a message
//! broker (`full`) or without one (`minimal`, `AXIAM__AMQP__ENABLED=false`).
//!
//! A value type in layer 0 so that the REST health endpoint, the REST and gRPC
//! reactor-administration surfaces and the composition root all speak the same
//! two words, and so the list of what the minimal profile gives up is written
//! down once.

use serde::{Deserialize, Serialize};

/// Which messaging profile the process was composed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentProfile {
    /// RabbitMQ is used: asynchronous authorization, external audit ingestion,
    /// reactors, cache invalidation across replicas, durable outbound queues.
    #[default]
    Full,
    /// No broker (`AXIAM__AMQP__ENABLED=false`). Single instance by definition;
    /// outbound delivery and mail run on in-process queues.
    Minimal,
}

/// What the minimal profile does not provide, as reported by `GET /health`
/// (`unavailable`) — the closed set the contract and the docs name.
pub const MINIMAL_PROFILE_UNAVAILABLE: [&str; 4] = [
    "reactors",
    "amqp_authz",
    "amqp_audit_ingestion",
    "decision_cache_broadcast",
];

impl DeploymentProfile {
    /// The wire name: `"full"` or `"minimal"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            DeploymentProfile::Full => "full",
            DeploymentProfile::Minimal => "minimal",
        }
    }

    /// Whether this is the broker-less profile.
    pub const fn is_minimal(self) -> bool {
        matches!(self, DeploymentProfile::Minimal)
    }

    /// The capabilities this profile does not provide: empty for `full`,
    /// [`MINIMAL_PROFILE_UNAVAILABLE`] for `minimal`.
    pub const fn unavailable(self) -> &'static [&'static str] {
        match self {
            DeploymentProfile::Full => &[],
            DeploymentProfile::Minimal => &MINIMAL_PROFILE_UNAVAILABLE,
        }
    }

    /// The sentence the reactor-administration surfaces answer with when a
    /// registration would be enabled in the minimal profile.
    pub const fn reactor_refusal_message() -> &'static str {
        "reactors are unavailable in the minimal profile (AXIAM__AMQP__ENABLED=false): \
         there is no broker to deliver interception events through, and an enabled \
         registration would apply its failure_policy to every dispatch — login.post_auth, \
         user.pre_create, user.pre_update and grant.pre_assign default to fail_closed, so \
         it would deny those operations for the tenant. Create or update the registration \
         with enabled: false, or run the full profile."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_names_are_pinned() {
        assert_eq!(DeploymentProfile::Full.as_str(), "full");
        assert_eq!(DeploymentProfile::Minimal.as_str(), "minimal");
        assert_eq!(
            serde_json::to_string(&DeploymentProfile::Minimal).unwrap(),
            "\"minimal\""
        );
        assert_eq!(DeploymentProfile::default(), DeploymentProfile::Full);
    }

    #[test]
    fn only_the_minimal_profile_reports_unavailable_features() {
        assert!(DeploymentProfile::Full.unavailable().is_empty());
        assert_eq!(
            DeploymentProfile::Minimal.unavailable(),
            [
                "reactors",
                "amqp_authz",
                "amqp_audit_ingestion",
                "decision_cache_broadcast"
            ]
        );
    }

    #[test]
    fn the_refusal_names_the_profile_and_the_fix() {
        let message = DeploymentProfile::reactor_refusal_message();
        assert!(message.contains("minimal profile"));
        assert!(message.contains("AXIAM__AMQP__ENABLED=false"));
        assert!(message.contains("enabled: false"));
    }
}

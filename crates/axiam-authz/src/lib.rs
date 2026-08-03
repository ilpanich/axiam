//! AXIAM AuthZ — Permission evaluation engine with resource hierarchy inheritance.

pub mod config;
pub mod decision_cache;
pub mod engine;
pub mod invalidation;
pub mod types;

pub use config::{AuthzConfig, BatchStrategy};
pub use decision_cache::{DecisionCache, DecisionCacheConfig, DecisionCacheStats};
pub use engine::AuthorizationEngine;
pub use invalidation::{InvalidationBroadcaster, InvalidationEvent};
pub use types::{AccessDecision, AccessRequest};

//! AXIAM AuthZ — Permission evaluation engine with resource hierarchy inheritance.

pub mod config;
pub mod engine;
pub mod types;

pub use config::AuthzConfig;
pub use engine::AuthorizationEngine;
pub use types::{AccessDecision, AccessRequest};

//! Domain models for AXIAM.
//!
//! All tenant-scoped models include a `tenant_id` field.
//! Organization and Tenant are the top-level multi-tenancy types.

pub mod audit;
pub mod certificate;
pub mod federation;
pub mod oauth2_client;
pub mod organization;
pub mod permission;
pub mod resource;
pub mod role;
pub mod scope;
pub mod service_account;
pub mod session;
pub mod tenant;
pub mod user;
pub mod webhook;

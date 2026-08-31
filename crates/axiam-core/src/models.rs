//! Domain models for AXIAM.
//!
//! All tenant-scoped models include a `tenant_id` field.
//! Organization and Tenant are the top-level multi-tenancy types.

pub mod audit;
pub mod certificate;
pub mod email;
pub mod email_template;
pub mod email_verification;
pub mod federation;
pub mod federation_claims;
pub mod gdpr;
pub mod group;
pub mod mail;
pub mod mds;
pub mod mfa_method;
pub mod notification_rule;
pub mod oauth2_client;
pub mod opaque;
pub mod organization;
pub mod password_history;
pub mod password_reset;
pub mod permission;
pub mod pgp_key;
pub mod reactor;
pub mod resource;
pub mod role;
pub mod scim_token;
pub mod scope;
pub mod service_account;
pub mod session;
pub mod settings;
pub mod tenant;
pub mod uma;
pub mod user;
pub mod webauthn_credential;
pub mod webauthn_policy;
pub mod webhook;

//! SurrealDB repository implementations.

mod audit;
mod ca_certificate;
mod certificate;
mod group;
mod oauth2_auth_code;
mod oauth2_client;
mod organization;
mod permission;
mod pgp_key;
mod resource;
mod role;
mod scope;
mod service_account;
mod session;
mod tenant;
mod user;
mod webhook;

pub use audit::SurrealAuditLogRepository;
pub use ca_certificate::SurrealCaCertificateRepository;
pub use certificate::SurrealCertificateRepository;
pub use group::SurrealGroupRepository;
pub use oauth2_auth_code::SurrealAuthorizationCodeRepository;
pub use oauth2_client::SurrealOAuth2ClientRepository;
pub use organization::SurrealOrganizationRepository;
pub use permission::SurrealPermissionRepository;
pub use pgp_key::SurrealPgpKeyRepository;
pub use resource::SurrealResourceRepository;
pub use role::SurrealRoleRepository;
pub use scope::SurrealScopeRepository;
pub use service_account::{SurrealServiceAccountRepository, hash_client_secret};
pub use session::SurrealSessionRepository;
pub use tenant::SurrealTenantRepository;
pub use user::{SurrealUserRepository, verify_password};
pub use webhook::SurrealWebhookRepository;

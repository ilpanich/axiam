//! SurrealDB repository implementations.

mod group;
mod organization;
mod permission;
mod resource;
mod role;
mod scope;
mod service_account;
mod session;
mod tenant;
mod user;

pub use group::SurrealGroupRepository;
pub use organization::SurrealOrganizationRepository;
pub use permission::SurrealPermissionRepository;
pub use resource::SurrealResourceRepository;
pub use role::SurrealRoleRepository;
pub use scope::SurrealScopeRepository;
pub use service_account::{SurrealServiceAccountRepository, hash_client_secret};
pub use session::SurrealSessionRepository;
pub use tenant::SurrealTenantRepository;
pub use user::{SurrealUserRepository, verify_password};

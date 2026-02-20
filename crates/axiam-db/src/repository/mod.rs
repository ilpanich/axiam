//! SurrealDB repository implementations.

mod group;
mod organization;
mod permission;
mod resource;
mod role;
mod scope;
mod tenant;
mod user;

pub use group::SurrealGroupRepository;
pub use organization::SurrealOrganizationRepository;
pub use permission::SurrealPermissionRepository;
pub use resource::SurrealResourceRepository;
pub use role::SurrealRoleRepository;
pub use scope::SurrealScopeRepository;
pub use tenant::SurrealTenantRepository;
pub use user::{SurrealUserRepository, verify_password};

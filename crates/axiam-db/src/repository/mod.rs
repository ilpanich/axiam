//! SurrealDB repository implementations.

mod organization;
mod tenant;

pub use organization::SurrealOrganizationRepository;
pub use tenant::SurrealTenantRepository;

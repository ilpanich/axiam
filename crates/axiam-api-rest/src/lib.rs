//! AXIAM REST API — HTTP extractors, authorization guards, and error handling.

pub mod authz;
pub mod error;
pub mod extractors;

pub use authz::{AuthzChecker, AuthzData, RequirePermission};
pub use error::AxiamApiError;
pub use extractors::auth::AuthenticatedUser;
pub use extractors::tenant::TenantContext;

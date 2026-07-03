//! REST transport (owned by 16-02): `AxiamClient` + builder, login/MFA/
//! refresh/logout, `check_access`/`batch_check`.

pub mod auth;
pub mod authz;

pub use auth::LoginResult;

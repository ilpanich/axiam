//! AXIAM Audit — Structured audit logging with append-only storage.

pub mod middleware;
pub mod service;

pub use middleware::AuditMiddleware;
pub use service::AuditService;

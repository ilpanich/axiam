//! AXIAM Audit — Structured audit logging with append-only storage.

pub mod middleware;
pub mod notification;
pub mod service;

pub use middleware::AuditMiddleware;
pub use notification::NotificationDispatcher;
pub use service::AuditService;

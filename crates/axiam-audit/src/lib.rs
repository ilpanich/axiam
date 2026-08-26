//! AXIAM Audit — Structured audit logging with append-only storage.

pub mod middleware;
pub mod notification;
pub mod service;

pub use middleware::{AuditAttribution, AuditEvent, AuditEventSink, AuditMiddleware};
pub use notification::{NotificationDispatcher, NotificationSink};
pub use service::AuditService;

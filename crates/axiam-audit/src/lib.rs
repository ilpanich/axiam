//! AXIAM Audit — Structured audit logging with append-only storage.

pub mod dead_letter;
pub mod loss;
pub mod middleware;
pub mod notification;
pub mod service;

pub use dead_letter::{DEAD_LETTER_FILE_ENV, DeadLetterWriter};
pub use loss::{RequestAuditLoss, RequestAuditLossSnapshot};
pub use middleware::{AuditAttribution, AuditEvent, AuditEventSink, AuditMiddleware};
pub use notification::{
    NotificationDispatcher, NotificationGate, NotificationSink, NotifyingAuditLog,
};
pub use service::AuditService;

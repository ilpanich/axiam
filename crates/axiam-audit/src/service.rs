//! Audit logging service — thin convenience wrapper over [`AuditLogRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::audit::{AuditLogEntry, CreateAuditLogEntry};
use axiam_core::repository::AuditLogRepository;

/// Audit logging service.
///
/// Provides a `log()` method that delegates to the underlying repository.
/// Clone-able so it can be shared across threads (e.g., passed into middleware
/// and handlers).
#[derive(Clone)]
pub struct AuditService<A> {
    repo: A,
}

impl<A: AuditLogRepository> AuditService<A> {
    pub fn new(repo: A) -> Self {
        Self { repo }
    }

    /// Append an audit log entry.
    pub async fn log(&self, entry: CreateAuditLogEntry) -> AxiamResult<AuditLogEntry> {
        self.repo.append(entry).await
    }
}

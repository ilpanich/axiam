//! **Test seam, never set in production** (#692): an audit repository whose
//! appends wait for a release, so a test can see *when* the audit drain runs.
//!
//! Without it the middleware's worker appends a request's row within
//! milliseconds of the response, long before the teardown, and a test that
//! finds the row at the exit has not shown the drain wrote it. With the hold
//! the row is queued but unwritten until the test releases it.

use axiam_core::error::AxiamResult;
use axiam_core::models::audit::{AuditLogEntry, CreateAuditLogEntry};
use axiam_core::repository::{AuditLogFilter, AuditLogRepository, PaginatedResult, Pagination};
use chrono::{DateTime, Utc};
use tokio::sync::watch;
use uuid::Uuid;

/// Appends wait until the value is `true`. The test keeps the sender.
pub type AuditHoldForTests = watch::Receiver<bool>;

/// `inner`, with [`AuditLogRepository::append`] held until released. Reads and
/// the two other writes pass straight through.
pub(crate) struct HeldAuditLog<A> {
    pub(crate) inner: A,
    pub(crate) released: AuditHoldForTests,
}

impl<A: AuditLogRepository> AuditLogRepository for HeldAuditLog<A> {
    fn datastore_now(&self) -> impl Future<Output = AxiamResult<DateTime<Utc>>> + Send {
        self.inner.datastore_now()
    }

    async fn append(&self, input: CreateAuditLogEntry) -> AxiamResult<AuditLogEntry> {
        let mut released = self.released.clone();
        // A dropped sender releases too: a test that ends must not leave the
        // worker waiting.
        let _ = released.wait_for(|open| *open).await;
        self.inner.append(input).await
    }

    fn list(
        &self,
        tenant_id: Uuid,
        filter: AuditLogFilter,
        pagination: Pagination,
    ) -> impl Future<Output = AxiamResult<PaginatedResult<AuditLogEntry>>> + Send {
        self.inner.list(tenant_id, filter, pagination)
    }

    fn list_system(
        &self,
        filter: AuditLogFilter,
        pagination: Pagination,
    ) -> impl Future<Output = AxiamResult<PaginatedResult<AuditLogEntry>>> + Send {
        self.inner.list_system(filter, pagination)
    }

    fn get_by_ids(
        &self,
        tenant_id: Uuid,
        ids: &[Uuid],
    ) -> impl Future<Output = AxiamResult<Vec<AuditLogEntry>>> + Send {
        self.inner.get_by_ids(tenant_id, ids)
    }

    fn pseudonymize_actor(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        pseudonym: &str,
    ) -> impl Future<Output = AxiamResult<u64>> + Send {
        self.inner.pseudonymize_actor(tenant_id, user_id, pseudonym)
    }

    fn prune_older_than(
        &self,
        cutoff: DateTime<Utc>,
    ) -> impl Future<Output = AxiamResult<u64>> + Send {
        self.inner.prune_older_than(cutoff)
    }
}

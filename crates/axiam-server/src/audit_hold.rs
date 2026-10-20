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

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use axiam_core::models::audit::{ActorType, AuditOutcome};

    use super::*;

    /// An inner repository that records which call reached it and answers with
    /// values the test can recognise.
    #[derive(Default)]
    struct Recorder {
        calls: Mutex<Vec<String>>,
    }

    impl Recorder {
        fn note(&self, call: impl Into<String>) {
            self.calls.lock().unwrap().push(call.into());
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    fn entry(id: Uuid, tenant_id: Uuid) -> AuditLogEntry {
        AuditLogEntry {
            id,
            tenant_id,
            actor_id: Uuid::nil(),
            actor_type: ActorType::System,
            action: "test.action".into(),
            resource_id: None,
            outcome: AuditOutcome::Success,
            ip_address: None,
            metadata: serde_json::json!({}),
            timestamp: Utc::now(),
        }
    }

    impl AuditLogRepository for Recorder {
        async fn datastore_now(&self) -> AxiamResult<DateTime<Utc>> {
            self.note("datastore_now");
            Ok(DateTime::<Utc>::UNIX_EPOCH)
        }

        async fn append(&self, input: CreateAuditLogEntry) -> AxiamResult<AuditLogEntry> {
            self.note(format!("append:{}", input.action));
            Ok(entry(Uuid::nil(), input.tenant_id))
        }

        async fn list(
            &self,
            tenant_id: Uuid,
            _: AuditLogFilter,
            pagination: Pagination,
        ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
            self.note("list");
            Ok(PaginatedResult {
                items: vec![entry(Uuid::nil(), tenant_id)],
                total: 7,
                offset: pagination.offset,
                limit: pagination.limit,
            })
        }

        async fn list_system(
            &self,
            _: AuditLogFilter,
            pagination: Pagination,
        ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
            self.note("list_system");
            Ok(PaginatedResult {
                items: vec![],
                total: 3,
                offset: pagination.offset,
                limit: pagination.limit,
            })
        }

        async fn get_by_ids(
            &self,
            tenant_id: Uuid,
            ids: &[Uuid],
        ) -> AxiamResult<Vec<AuditLogEntry>> {
            self.note("get_by_ids");
            Ok(ids.iter().map(|id| entry(*id, tenant_id)).collect())
        }

        async fn pseudonymize_actor(&self, _: Uuid, _: Uuid, pseudonym: &str) -> AxiamResult<u64> {
            self.note(format!("pseudonymize_actor:{pseudonym}"));
            Ok(11)
        }

        async fn prune_older_than(&self, _: DateTime<Utc>) -> AxiamResult<u64> {
            self.note("prune_older_than");
            Ok(13)
        }
    }

    fn new_entry(action: &str) -> CreateAuditLogEntry {
        CreateAuditLogEntry {
            tenant_id: Uuid::new_v4(),
            actor_id: Uuid::nil(),
            actor_type: ActorType::System,
            action: action.into(),
            resource_id: None,
            outcome: AuditOutcome::Success,
            ip_address: None,
            metadata: None,
        }
    }

    fn held(open: bool) -> (watch::Sender<bool>, HeldAuditLog<Recorder>) {
        let (tx, rx) = watch::channel(open);
        (
            tx,
            HeldAuditLog {
                inner: Recorder::default(),
                released: rx,
            },
        )
    }

    /// The point of the seam: the row is not written while the hold is closed,
    /// and is written, once and unchanged, when the test opens it.
    #[tokio::test]
    async fn an_append_waits_for_the_release_then_reaches_the_inner_repository() {
        let (release, repo) = held(false);
        let input = new_entry("hold.append");

        let waiting =
            tokio::time::timeout(Duration::from_millis(50), repo.append(input.clone())).await;
        assert!(
            waiting.is_err(),
            "append must not complete while the hold is closed"
        );
        assert!(
            repo.inner.calls().is_empty(),
            "nothing may reach the inner repository before the release"
        );

        release.send(true).unwrap();
        let written = repo
            .append(input.clone())
            .await
            .expect("released append succeeds");
        assert_eq!(written.tenant_id, input.tenant_id);
        assert_eq!(repo.inner.calls(), vec!["append:hold.append".to_string()]);
    }

    /// A release that arrives while an append is already waiting wakes it.
    #[tokio::test]
    async fn a_release_wakes_an_append_already_waiting() {
        let (release, repo) = held(false);
        let repo = std::sync::Arc::new(repo);
        let waiter = {
            let repo = repo.clone();
            tokio::spawn(async move { repo.append(new_entry("hold.waiting")).await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished(), "the append is held");

        release.send(true).unwrap();
        waiter
            .await
            .unwrap()
            .expect("append completes after the release");
        assert_eq!(repo.inner.calls(), vec!["append:hold.waiting".to_string()]);
    }

    /// A test that ends drops the sender; the worker must not wait forever.
    #[tokio::test]
    async fn a_dropped_sender_releases_the_hold() {
        let (release, repo) = held(false);
        drop(release);
        tokio::time::timeout(
            Duration::from_secs(5),
            repo.append(new_entry("hold.dropped")),
        )
        .await
        .expect("a dropped sender releases the hold")
        .expect("append succeeds");
        assert_eq!(repo.inner.calls(), vec!["append:hold.dropped".to_string()]);
    }

    /// Everything but `append` passes straight through, closed hold or not.
    #[tokio::test]
    async fn reads_and_the_other_writes_pass_straight_through_a_closed_hold() {
        let (_release, repo) = held(false);
        let tenant = Uuid::new_v4();
        let id = Uuid::new_v4();

        assert_eq!(
            repo.datastore_now().await.unwrap(),
            DateTime::<Utc>::UNIX_EPOCH
        );

        let page = Pagination {
            offset: 5,
            limit: 9,
            search: None,
        };
        let listed = repo
            .list(tenant, AuditLogFilter::default(), page.clone())
            .await
            .unwrap();
        assert_eq!((listed.total, listed.offset, listed.limit), (7, 5, 9));
        assert_eq!(listed.items[0].tenant_id, tenant);

        let system = repo
            .list_system(AuditLogFilter::default(), page)
            .await
            .unwrap();
        assert_eq!((system.total, system.items.len()), (3, 0));

        let fetched = repo.get_by_ids(tenant, &[id]).await.unwrap();
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].id, id);

        assert_eq!(
            repo.pseudonymize_actor(tenant, id, "p-1").await.unwrap(),
            11
        );
        assert_eq!(repo.prune_older_than(Utc::now()).await.unwrap(), 13);

        assert_eq!(
            repo.inner.calls(),
            vec![
                "datastore_now",
                "list",
                "list_system",
                "get_by_ids",
                "pseudonymize_actor:p-1",
                "prune_older_than",
            ]
        );
    }
}

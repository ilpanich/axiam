//! `recent_health` — what the reactor detail view reports, and how it fails.
//!
//! Read by the REST handler and the gRPC service to show an operator whether a
//! reactor has been timing out or vetoing. Two counts that look alike and are
//! computed by different means, and both fail soft, none of which was
//! asserted anywhere.

use axiam_amqp::reactor::{AUDIT_ACTION_DENIED, AUDIT_ACTION_FAILURE, recent_health};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::audit::{ActorType, AuditLogEntry, AuditOutcome, CreateAuditLogEntry};
use axiam_core::repository::{AuditLogFilter, AuditLogRepository, PaginatedResult, Pagination};
use chrono::Utc;
use uuid::Uuid;

fn entry(
    tenant_id: Uuid,
    reactor_id: Uuid,
    action: &str,
    failure_kind: Option<&str>,
) -> AuditLogEntry {
    AuditLogEntry {
        id: Uuid::new_v4(),
        tenant_id,
        actor_id: Uuid::nil(),
        actor_type: ActorType::System,
        action: action.to_string(),
        resource_id: Some(reactor_id),
        outcome: AuditOutcome::Failure,
        ip_address: None,
        metadata: match failure_kind {
            Some(kind) => serde_json::json!({ "failure_kind": kind }),
            None => serde_json::json!({}),
        },
        timestamp: Utc::now(),
    }
}

/// Answers `failures` to a query for [`AUDIT_ACTION_FAILURE`] and a page whose
/// `total` is `veto_total` to a query for [`AUDIT_ACTION_DENIED`]; either can
/// be turned into an error instead.
#[derive(Default)]
struct AuditTrail {
    failures: Vec<AuditLogEntry>,
    veto_total: u64,
    fail_on_failures: bool,
    fail_on_vetoes: bool,
}

impl AuditLogRepository for AuditTrail {
    async fn append(&self, _input: CreateAuditLogEntry) -> AxiamResult<AuditLogEntry> {
        unreachable!("not exercised by this test")
    }

    async fn list(
        &self,
        _tenant_id: Uuid,
        filter: AuditLogFilter,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        assert!(
            filter.from.is_some(),
            "both queries must be bounded by the lookback window, or the counts \
             would be lifetime totals presented as recent"
        );
        let action = filter.action.as_deref().unwrap_or_default();
        if action == AUDIT_ACTION_FAILURE {
            if self.fail_on_failures {
                return Err(AxiamError::Internal("audit trail unreadable".into()));
            }
            // The repository honours the page size; the caller's
            // `failure_sample_limit` is what bounds this.
            let items: Vec<_> = self
                .failures
                .iter()
                .take(pagination.limit as usize)
                .cloned()
                .collect();
            let total = self.failures.len() as u64;
            return Ok(PaginatedResult {
                items,
                total,
                offset: 0,
                limit: pagination.limit,
            });
        }
        assert_eq!(
            action, AUDIT_ACTION_DENIED,
            "recent_health issues exactly two queries: failures and vetoes"
        );
        if self.fail_on_vetoes {
            return Err(AxiamError::Internal("audit trail unreadable".into()));
        }
        Ok(PaginatedResult {
            items: Vec::new(),
            total: self.veto_total,
            offset: 0,
            limit: pagination.limit,
        })
    }

    async fn list_system(
        &self,
        _filter: AuditLogFilter,
        _pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        unreachable!("not exercised by this test")
    }
    async fn get_by_ids(&self, _t: Uuid, _ids: &[Uuid]) -> AxiamResult<Vec<AuditLogEntry>> {
        unreachable!("not exercised by this test")
    }
    async fn pseudonymize_actor(&self, _t: Uuid, _u: Uuid, _p: &str) -> AxiamResult<u64> {
        unreachable!("not exercised by this test")
    }
    async fn prune_older_than(&self, _c: chrono::DateTime<Utc>) -> AxiamResult<u64> {
        unreachable!("not exercised by this test")
    }
}

fn lookback() -> chrono::Duration {
    chrono::Duration::hours(1)
}

#[tokio::test]
async fn only_failures_marked_as_timeouts_are_counted_as_timeouts() {
    // `AUDIT_ACTION_FAILURE` covers every way a dispatch can fail; the timeout
    // count is narrower, filtered client-side on `metadata.failure_kind`. A
    // transport error or a malformed reply is a failure and NOT a timeout, and
    // conflating them would tell an operator their reactor is slow when it is
    // actually erroring.
    let tenant = Uuid::new_v4();
    let reactor = Uuid::new_v4();
    let trail = AuditTrail {
        failures: vec![
            entry(tenant, reactor, AUDIT_ACTION_FAILURE, Some("timeout")),
            entry(tenant, reactor, AUDIT_ACTION_FAILURE, Some("transport")),
            entry(tenant, reactor, AUDIT_ACTION_FAILURE, None),
            entry(tenant, reactor, AUDIT_ACTION_FAILURE, Some("timeout")),
        ],
        ..Default::default()
    };

    let health = recent_health(&trail, tenant, reactor, lookback(), 100).await;

    assert_eq!(health.recent_timeout_count, 2);
}

#[tokio::test]
async fn the_timeout_count_is_a_sample_while_the_veto_count_is_a_total() {
    // The two numbers sit side by side in the same struct and are computed
    // differently: timeouts are counted from the page actually returned, so
    // `failure_sample_limit` caps them, while vetoes come from the page's
    // `total` and are not capped at all. A reader who assumes both are exact
    // will under-read timeouts on a busy reactor — worth pinning so the
    // asymmetry is deliberate rather than incidental.
    let tenant = Uuid::new_v4();
    let reactor = Uuid::new_v4();
    let trail = AuditTrail {
        failures: (0..10)
            .map(|_| entry(tenant, reactor, AUDIT_ACTION_FAILURE, Some("timeout")))
            .collect(),
        veto_total: 500,
        ..Default::default()
    };

    let health = recent_health(&trail, tenant, reactor, lookback(), 3).await;

    assert_eq!(
        health.recent_timeout_count, 3,
        "timeouts are bounded by the sample limit"
    );
    assert_eq!(
        health.recent_veto_count, 500,
        "vetoes are the trail's total, not a sampled count"
    );
}

#[tokio::test]
async fn an_unreadable_audit_trail_reports_zero_rather_than_failing_the_view() {
    // Fail-soft, and deliberately so: this feeds a detail view, and an audit
    // store hiccup should not take the whole reactor page down. The cost is
    // that zero means either "healthy" or "unknown", which is why each count
    // falls back independently — one unreadable query must not zero the other.
    let tenant = Uuid::new_v4();
    let reactor = Uuid::new_v4();

    let both_down = AuditTrail {
        fail_on_failures: true,
        fail_on_vetoes: true,
        ..Default::default()
    };
    let health = recent_health(&both_down, tenant, reactor, lookback(), 100).await;
    assert_eq!(health.recent_timeout_count, 0);
    assert_eq!(health.recent_veto_count, 0);

    let only_failures_down = AuditTrail {
        fail_on_failures: true,
        veto_total: 7,
        ..Default::default()
    };
    let health = recent_health(&only_failures_down, tenant, reactor, lookback(), 100).await;
    assert_eq!(health.recent_timeout_count, 0);
    assert_eq!(
        health.recent_veto_count, 7,
        "an unreadable failure query must not zero the veto count too"
    );
}

#[tokio::test]
async fn a_reactor_with_a_quiet_trail_reports_clean() {
    let health = recent_health(
        &AuditTrail::default(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        lookback(),
        100,
    )
    .await;

    assert_eq!(health.recent_timeout_count, 0);
    assert_eq!(health.recent_veto_count, 0);
}

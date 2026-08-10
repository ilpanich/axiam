//! Reactor dispatch (X1) — the interceptor chain and its failure policy.
//!
//! Everything that decides an outcome lives here and is broker-free: the chain
//! talks to a [`ReactorTransport`], and the lapin implementation of that trait
//! is the only part that knows AMQP exists. That split is deliberate — the
//! rules about what a third party may do to a token are the part worth testing
//! exhaustively, and a test that needs a running broker is a test that gets
//! skipped.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use axiam_core::models::reactor::{
    FailurePolicy, Reactor, ReactorMode, ReactorOutcome, event_spec,
};

use super::protocol::{ReactorReply, ReplyRejection};

/// Default cap on interceptions in flight per tenant. A slow actor must not be
/// able to hold the token path's task budget hostage.
pub const DEFAULT_MAX_IN_FLIGHT: usize = 64;

/// Total wall-clock ceiling for one event's whole chain, regardless of how the
/// individual `timeout_ms` values add up. Ten reactors at 5 s each is 50 s of
/// held request; this is the number that stops it.
pub const MAX_CHAIN_BUDGET_MS: u32 = 5_000;

/// Why an interceptor produced no usable answer. Each maps to the
/// registration's [`FailurePolicy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchFailure {
    /// The reactor did not answer inside its window.
    Timeout,
    /// The chain's total budget ran out before this reactor was reached.
    BudgetExhausted,
    /// Broker or serialization failure.
    Transport(String),
    /// A reply arrived but was not usable.
    Rejected(ReplyRejection),
    /// The per-tenant in-flight cap was already reached.
    Overloaded,
}

impl std::fmt::Display for DispatchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => write!(f, "reactor timed out"),
            Self::BudgetExhausted => write!(f, "chain budget exhausted before this reactor"),
            Self::Transport(e) => write!(f, "reactor transport failure: {e}"),
            Self::Rejected(r) => write!(f, "reactor reply rejected: {r}"),
            Self::Overloaded => write!(f, "reactor concurrency cap reached"),
        }
    }
}

/// One round-trip to one reactor. Implemented by the lapin transport in
/// production and by a scripted double in tests.
pub trait ReactorTransport: Send + Sync {
    /// Publish the event to `reactor` and await its reply within
    /// `timeout_ms`. Returns the raw reply; validation is the chain's job, so
    /// a transport can never accidentally widen what counts as acceptable.
    fn round_trip(
        &self,
        reactor: &Reactor,
        event: &'static str,
        correlation_id: Uuid,
        payload: serde_json::Value,
        timeout_ms: u32,
    ) -> impl std::future::Future<Output = Result<ReactorReply, DispatchFailure>> + Send;

    /// Publish to a listener. Fire-and-forget: a listener cannot affect an
    /// outcome, so a failure here is logged and nothing more.
    fn publish_listen(
        &self,
        reactor: &Reactor,
        event: &'static str,
        payload: serde_json::Value,
    ) -> impl std::future::Future<Output = Result<(), DispatchFailure>> + Send;
}

/// What one event's chain produced, plus what to audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainResult {
    pub outcome: ReactorOutcome,
    /// Every failure the chain absorbed, in order, with the reactor that
    /// caused it. A `fail_open` timeout is invisible in the outcome and must
    /// not be invisible in the audit trail — that is the whole difference
    /// between "no reactor was configured" and "the reactor never answered".
    pub failures: Vec<(Uuid, DispatchFailure)>,
}

/// Resolve one reactor's failure through its policy.
fn apply_policy(policy: FailurePolicy, failure: &DispatchFailure) -> ReactorOutcome {
    match policy {
        FailurePolicy::FailOpen => ReactorOutcome::Allow,
        FailurePolicy::FailClosed => ReactorOutcome::Deny {
            reason: format!("reactor unavailable ({failure})"),
        },
    }
}

/// Run the interceptor chain for one event.
///
/// # The composition rules, and why each is the way it is
///
/// - **Deny short-circuits.** Once any reactor refuses, later reactors are not
///   consulted. They cannot overturn it (there is no "allow-override"), so
///   calling them would spend the caller's latency to learn nothing.
/// - **Patches accumulate, later wins per key.** Reactors run in priority
///   order and each sees the prior patch, so a higher-priority reactor's field
///   is the one that survives. Merging by union-with-last-write is the only
///   rule that makes the chain's result depend on the declared priority rather
///   than on message timing.
/// - **`require_mfa` is sticky.** Once any reactor demands step-up, no later
///   reactor can clear it. A reactor that wanted step-up and got overruled by
///   one registered after it would be a security control with a race in it.
/// - **The budget is wall-clock, not a sum.** Each reactor gets the smaller of
///   its own `timeout_ms` and what remains of [`MAX_CHAIN_BUDGET_MS`]. A chain
///   that runs out of budget applies the *remaining* reactors' own policies —
///   so an unreached `fail_closed` veto still denies, which is what makes the
///   budget a bound on latency rather than a way to skip a security check by
///   registering slow reactors ahead of it.
pub async fn run_chain<T: ReactorTransport>(
    transport: &T,
    master_key: &[u8],
    reactors: &[Reactor],
    event: &'static str,
    base_payload: serde_json::Value,
    now: impl Fn() -> DateTime<Utc>,
    elapsed_ms: impl Fn() -> u32,
) -> ChainResult {
    let mut failures = Vec::new();
    let mut patch: BTreeMap<String, String> = BTreeMap::new();
    let mut require_mfa = false;

    let Some(spec) = event_spec(event) else {
        // An event nobody registered in the registry cannot be dispatched.
        // Returning Allow is correct rather than lenient: no reactor could
        // have been *validly* registered for it, so there is nothing to wait
        // for.
        return ChainResult {
            outcome: ReactorOutcome::Allow,
            failures,
        };
    };

    for reactor in reactors.iter().filter(|r| r.mode == ReactorMode::Intercept) {
        let spent = elapsed_ms();
        let remaining = MAX_CHAIN_BUDGET_MS.saturating_sub(spent);
        if remaining == 0 {
            let failure = DispatchFailure::BudgetExhausted;
            let outcome = apply_policy(reactor.failure_policy, &failure);
            failures.push((reactor.id, failure));
            if let ReactorOutcome::Deny { reason } = outcome {
                return ChainResult {
                    outcome: ReactorOutcome::Deny { reason },
                    failures,
                };
            }
            continue;
        }

        // Compose the payload the reactor sees: the original plus whatever
        // earlier reactors in the chain patched, so a later reactor decides
        // against the state that will actually be committed.
        let mut payload = base_payload.clone();
        if !patch.is_empty()
            && let Some(obj) = payload.as_object_mut()
        {
            obj.insert(
                "_reactor_patch".into(),
                serde_json::to_value(&patch).unwrap_or(serde_json::Value::Null),
            );
        }

        let correlation_id = Uuid::new_v4();
        let budget = reactor.timeout_ms.min(remaining);

        let step = match transport
            .round_trip(reactor, event, correlation_id, payload, budget)
            .await
        {
            Ok(reply) => reply
                .into_outcome(
                    // The CHAIN verifies the signature, not the transport.
                    // A transport that validated replies could quietly widen
                    // what counts as acceptable; keeping the check here means
                    // there is exactly one place that decides a reply is
                    // authentic, and it is the same place that decides what
                    // the reply is allowed to say.
                    master_key,
                    correlation_id,
                    reactor.tenant_id,
                    spec,
                    now(),
                    chrono::Duration::seconds(crate::messages::DEFAULT_FRESHNESS_SKEW_SECS),
                )
                .map_err(DispatchFailure::Rejected),
            Err(e) => Err(e),
        };

        match step {
            Ok(ReactorOutcome::Deny { reason }) => {
                return ChainResult {
                    outcome: ReactorOutcome::Deny { reason },
                    failures,
                };
            }
            Ok(ReactorOutcome::Mutate { patch: p }) => {
                patch.extend(p);
            }
            Ok(ReactorOutcome::RequireMfa) => {
                require_mfa = true;
            }
            Ok(ReactorOutcome::Allow) => {}
            Err(failure) => {
                let outcome = apply_policy(reactor.failure_policy, &failure);
                failures.push((reactor.id, failure));
                if let ReactorOutcome::Deny { reason } = outcome {
                    return ChainResult {
                        outcome: ReactorOutcome::Deny { reason },
                        failures,
                    };
                }
            }
        }
    }

    let outcome = if require_mfa {
        ReactorOutcome::RequireMfa
    } else if patch.is_empty() {
        ReactorOutcome::Allow
    } else {
        ReactorOutcome::Mutate { patch }
    };

    ChainResult { outcome, failures }
}

/// A gate that runs no reactors, used when the feature is off.
///
/// Exists so `axiam-auth` and `axiam-oauth2` have exactly one code path
/// whether or not reactors are configured. A call site that branches on
/// `Option<Gate>` is a call site where the disabled build and the enabled
/// build can drift.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopReactorGate;

impl axiam_core::models::reactor::ReactorGate for NoopReactorGate {
    async fn intercept(
        &self,
        _tenant_id: Uuid,
        _event: &'static str,
        _payload: serde_json::Value,
    ) -> ReactorOutcome {
        ReactorOutcome::Allow
    }
}

/// Bounds concurrent interceptions per tenant.
#[derive(Debug, Clone)]
pub struct InFlightLimiter {
    permits: Arc<tokio::sync::Semaphore>,
}

impl InFlightLimiter {
    pub fn new(max_in_flight: usize) -> Self {
        Self {
            permits: Arc::new(tokio::sync::Semaphore::new(max_in_flight.max(1))),
        }
    }

    /// Take a permit, or report overload immediately.
    ///
    /// `try_acquire`, never `acquire`: queueing behind the cap would turn a
    /// concurrency bound into an unbounded latency bound, which is the
    /// failure this cap exists to prevent. Breaching it applies the failure
    /// policy right away — documented back-pressure, not a hidden wait.
    pub fn try_enter(&self) -> Result<tokio::sync::SemaphorePermit<'_>, DispatchFailure> {
        self.permits
            .try_acquire()
            .map_err(|_| DispatchFailure::Overloaded)
    }
}

impl Default for InFlightLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_IN_FLIGHT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::CURRENT_KEY_VERSION;
    use crate::reactor::protocol::ReplyDecision;
    use std::sync::Mutex;

    const MASTER: &[u8] = b"master-key-for-reactor-dispatch-tests";

    fn reactor(name: &str, priority: i32, policy: FailurePolicy, timeout_ms: u32) -> Reactor {
        Reactor {
            id: Uuid::new_v4(),
            tenant_id: TENANT.with(|t| *t),
            name: name.into(),
            description: String::new(),
            events: vec!["token.pre_issue".into()],
            mode: ReactorMode::Intercept,
            priority,
            timeout_ms,
            failure_policy: policy,
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_seen_at: None,
        }
    }

    thread_local! {
        static TENANT: Uuid = Uuid::new_v4();
    }

    /// Scripted transport: one canned step per reactor, by name.
    enum Step {
        Reply(ReplyDecision, Option<BTreeMap<String, String>>, bool),
        Fail(DispatchFailure),
    }

    struct Scripted {
        steps: Mutex<Vec<(String, Step)>>,
        called: Mutex<Vec<String>>,
    }

    impl Scripted {
        fn new(steps: Vec<(&str, Step)>) -> Self {
            Self {
                steps: Mutex::new(steps.into_iter().map(|(n, s)| (n.to_string(), s)).collect()),
                called: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.called.lock().unwrap().clone()
        }
    }

    impl ReactorTransport for Scripted {
        async fn round_trip(
            &self,
            reactor: &Reactor,
            event: &'static str,
            correlation_id: Uuid,
            _payload: serde_json::Value,
            _timeout_ms: u32,
        ) -> Result<ReactorReply, DispatchFailure> {
            self.called.lock().unwrap().push(reactor.name.clone());
            let steps = self.steps.lock().unwrap();
            let step = steps
                .iter()
                .find(|(n, _)| *n == reactor.name)
                .map(|(_, s)| s)
                .expect("scripted step for reactor");

            match step {
                Step::Fail(f) => Err(f.clone()),
                Step::Reply(decision, patch, require_mfa) => {
                    let mut reply = ReactorReply {
                        correlation_id,
                        tenant_id: reactor.tenant_id,
                        event: event.to_string(),
                        decision: *decision,
                        reason: Some("scripted".into()),
                        patch: patch.clone(),
                        require_mfa: *require_mfa,
                        key_version: CURRENT_KEY_VERSION,
                        nonce: Uuid::new_v4(),
                        issued_at: Utc::now(),
                        hmac_signature: None,
                    };
                    reply.sign(MASTER).unwrap();
                    Ok(reply)
                }
            }
        }

        async fn publish_listen(
            &self,
            _reactor: &Reactor,
            _event: &'static str,
            _payload: serde_json::Value,
        ) -> Result<(), DispatchFailure> {
            Ok(())
        }
    }

    fn allow() -> Step {
        Step::Reply(ReplyDecision::Allow, None, false)
    }
    fn deny() -> Step {
        Step::Reply(ReplyDecision::Deny, None, false)
    }
    fn mutate(pairs: &[(&str, &str)]) -> Step {
        Step::Reply(
            ReplyDecision::Mutate,
            Some(
                pairs
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            ),
            false,
        )
    }

    async fn run(t: &Scripted, reactors: &[Reactor]) -> ChainResult {
        run_chain(
            t,
            MASTER,
            reactors,
            "token.pre_issue",
            serde_json::json!({"sub": "alice"}),
            Utc::now,
            || 0,
        )
        .await
    }

    #[tokio::test]
    async fn no_reactors_means_allow_and_no_failures() {
        let t = Scripted::new(vec![]);
        let result = run(&t, &[]).await;
        assert_eq!(result.outcome, ReactorOutcome::Allow);
        assert!(result.failures.is_empty());
    }

    #[tokio::test]
    async fn patches_accumulate_in_priority_order_with_later_winning() {
        let first = reactor("first", 1, FailurePolicy::FailOpen, 500);
        let second = reactor("second", 2, FailurePolicy::FailOpen, 500);
        let t = Scripted::new(vec![
            (
                "first",
                mutate(&[("ext.a", "1"), ("ext.shared", "from-first")]),
            ),
            (
                "second",
                mutate(&[("ext.b", "2"), ("ext.shared", "from-second")]),
            ),
        ]);

        let result = run(&t, &[first, second]).await;
        match result.outcome {
            ReactorOutcome::Mutate { patch } => {
                assert_eq!(patch["ext.a"], "1");
                assert_eq!(patch["ext.b"], "2");
                assert_eq!(
                    patch["ext.shared"], "from-second",
                    "the later reactor in priority order wins the key"
                );
            }
            other => panic!("expected a mutation, got {other:?}"),
        }
        assert_eq!(t.calls(), vec!["first", "second"]);
    }

    #[tokio::test]
    async fn a_deny_short_circuits_the_rest_of_the_chain() {
        let first = reactor("first", 1, FailurePolicy::FailOpen, 500);
        let second = reactor("second", 2, FailurePolicy::FailOpen, 500);
        let t = Scripted::new(vec![("first", deny()), ("second", allow())]);

        let result = run(&t, &[first, second]).await;
        assert!(!result.outcome.permits());
        assert_eq!(
            t.calls(),
            vec!["first"],
            "nothing later can overturn a deny, so nothing later should be asked"
        );
    }

    /// A `fail_open` timeout must be invisible in the outcome and visible in
    /// the audit trail. Those two together are the whole contract.
    #[tokio::test]
    async fn a_fail_open_timeout_allows_but_is_still_recorded() {
        let r = reactor("flaky", 1, FailurePolicy::FailOpen, 500);
        let id = r.id;
        let t = Scripted::new(vec![("flaky", Step::Fail(DispatchFailure::Timeout))]);

        let result = run(&t, &[r]).await;
        assert_eq!(result.outcome, ReactorOutcome::Allow);
        assert_eq!(result.failures, vec![(id, DispatchFailure::Timeout)]);
    }

    #[tokio::test]
    async fn a_fail_closed_timeout_denies() {
        let r = reactor("fraud-check", 1, FailurePolicy::FailClosed, 500);
        let t = Scripted::new(vec![("fraud-check", Step::Fail(DispatchFailure::Timeout))]);

        let result = run(&t, &[r]).await;
        assert!(!result.outcome.permits());
        assert_eq!(result.failures.len(), 1);
    }

    /// A rejected reply is not a softer failure than no reply. A reactor that
    /// answers with a forbidden patch has failed, and its policy decides.
    #[tokio::test]
    async fn a_rejected_reply_takes_the_same_path_as_a_timeout() {
        let r = reactor("liar", 1, FailurePolicy::FailClosed, 500);
        let t = Scripted::new(vec![("liar", mutate(&[("sub", "root")]))]);

        let result = run(&t, &[r]).await;
        assert!(!result.outcome.permits());
        assert!(matches!(
            result.failures[0].1,
            DispatchFailure::Rejected(ReplyRejection::ForbiddenPatchField(_))
        ));
    }

    /// A fail-open reactor failing must not stop a later fail-closed veto from
    /// being consulted.
    #[tokio::test]
    async fn a_fail_open_failure_does_not_end_the_chain() {
        let flaky = reactor("flaky", 1, FailurePolicy::FailOpen, 500);
        let veto = reactor("veto", 2, FailurePolicy::FailClosed, 500);
        let t = Scripted::new(vec![
            ("flaky", Step::Fail(DispatchFailure::Timeout)),
            ("veto", deny()),
        ]);

        let result = run(&t, &[flaky, veto]).await;
        assert!(!result.outcome.permits());
        assert_eq!(t.calls(), vec!["flaky", "veto"]);
    }

    #[tokio::test]
    async fn require_mfa_is_sticky_across_the_chain() {
        let asks = reactor("asks", 1, FailurePolicy::FailOpen, 500);
        let quiet = reactor("quiet", 2, FailurePolicy::FailOpen, 500);
        let t = Scripted::new(vec![
            ("asks", Step::Reply(ReplyDecision::Allow, None, true)),
            ("quiet", allow()),
        ]);

        let result = run_chain(
            &t,
            MASTER,
            &[asks, quiet],
            "login.post_auth",
            serde_json::json!({}),
            Utc::now,
            || 0,
        )
        .await;

        assert_eq!(
            result.outcome,
            ReactorOutcome::RequireMfa,
            "a later reactor must not be able to clear an earlier step-up demand"
        );
    }

    /// The budget bounds latency; it must not become a way to skip a veto by
    /// registering slow reactors ahead of it.
    #[tokio::test]
    async fn an_exhausted_budget_still_applies_each_remaining_reactors_policy() {
        let lenient = reactor("lenient", 1, FailurePolicy::FailOpen, 500);
        let veto = reactor("veto", 2, FailurePolicy::FailClosed, 500);
        let t = Scripted::new(vec![("lenient", allow()), ("veto", allow())]);

        // Pretend the whole budget is already spent.
        let result = run_chain(
            &t,
            MASTER,
            &[lenient, veto],
            "token.pre_issue",
            serde_json::json!({}),
            Utc::now,
            || MAX_CHAIN_BUDGET_MS,
        )
        .await;

        assert!(
            !result.outcome.permits(),
            "an unreached fail_closed reactor must still deny"
        );
        assert!(t.calls().is_empty(), "no reactor should be contacted");
        assert_eq!(result.failures.len(), 2);
        assert!(
            result
                .failures
                .iter()
                .all(|(_, f)| *f == DispatchFailure::BudgetExhausted)
        );
    }

    /// Listeners are not interceptors and must never be waited on, even when
    /// they are registered for the same event.
    #[tokio::test]
    async fn a_listener_registered_on_an_intercepted_event_is_not_consulted() {
        let mut listener = reactor("observer", 1, FailurePolicy::FailClosed, 500);
        listener.mode = ReactorMode::Listen;
        let t = Scripted::new(vec![]);

        let result = run(&t, &[listener]).await;
        assert_eq!(result.outcome, ReactorOutcome::Allow);
        assert!(t.calls().is_empty());
    }

    #[tokio::test]
    async fn an_unregistered_event_dispatches_to_nothing() {
        let r = reactor("any", 1, FailurePolicy::FailClosed, 500);
        let t = Scripted::new(vec![]);

        let result = run_chain(
            &t,
            MASTER,
            &[r],
            "authz.check",
            serde_json::json!({}),
            Utc::now,
            || 0,
        )
        .await;

        assert_eq!(result.outcome, ReactorOutcome::Allow);
        assert!(t.calls().is_empty());
    }

    #[test]
    fn the_in_flight_limiter_reports_overload_rather_than_queueing() {
        let limiter = InFlightLimiter::new(2);
        let _a = limiter.try_enter().expect("first permit");
        let _b = limiter.try_enter().expect("second permit");
        assert_eq!(
            limiter.try_enter().unwrap_err(),
            DispatchFailure::Overloaded
        );
    }

    #[test]
    fn a_zero_cap_is_raised_to_one_rather_than_deadlocking() {
        let limiter = InFlightLimiter::new(0);
        assert!(limiter.try_enter().is_ok());
    }

    #[test]
    fn failure_policy_maps_every_failure_the_same_way() {
        for failure in [
            DispatchFailure::Timeout,
            DispatchFailure::BudgetExhausted,
            DispatchFailure::Overloaded,
            DispatchFailure::Transport("broker down".into()),
            DispatchFailure::Rejected(ReplyRejection::BadSignature),
        ] {
            assert_eq!(
                apply_policy(FailurePolicy::FailOpen, &failure),
                ReactorOutcome::Allow
            );
            assert!(!apply_policy(FailurePolicy::FailClosed, &failure).permits());
        }
    }
}

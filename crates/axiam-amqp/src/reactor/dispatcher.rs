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

    /// Whether this transport can actually deliver anything (SEC-101).
    ///
    /// `false` only for [`UnavailableReactorTransport`]. The REST layer reads
    /// it through [`axiam_core::models::reactor::DynReactorGate`] and refuses
    /// to accept a reactor registration while it is false, because
    /// registering one against a transport that cannot deliver is a
    /// self-inflicted, tenant-wide, *complete* login outage created by a
    /// supported admin action: the transport fails every dispatch,
    /// `login.post_auth` defaults to `fail_closed`, and the only warning would
    /// be a `tracing::warn!` emitted once at boot, for every deployment
    /// including the majority that will never register a reactor — which is
    /// the classic recipe for a warning nobody reads.
    ///
    /// This is a statement about the transport's *capability*, not its
    /// current health, and the distinction is load-bearing now that
    /// [`crate::reactor::transport::LapinReactorTransport`] is what
    /// `axiam-server` composes: it answers `true` even while its broker
    /// session is down, and each registration's `failure_policy` decides what
    /// a dispatch during the outage costs. Returning `false` on a blip would
    /// turn a broker outage into a registration outage.
    ///
    /// Defaults to `true`, so a real transport says nothing and a test double
    /// needs no change.
    fn can_dispatch(&self) -> bool {
        true
    }
}

/// The transport for a build that composes no broker.
///
/// # Why this exists rather than a `None`
///
/// Composing the gate with *no* transport would mean composing no gate, and a
/// deployment whose registered `fail_closed` fraud check silently does nothing
/// is the exact failure mode reactors exist to avoid — an operator who
/// registered one believes their logins are protected.
///
/// So every round trip fails as `Transport`, which §22.8 puts in the same
/// closed "no usable reply" set as a timeout, and **each registration's own
/// failure policy decides what that costs**:
///
/// * a tenant with **no** registered reactor is completely unaffected — the
///   routing table returns an empty list and the gate never reaches a
///   transport;
/// * a registered `fail_open` reactor (the `token.pre_issue` default) allows,
///   and every dispatch is audited and counted;
/// * a registered `fail_closed` reactor (the `login.post_auth`,
///   `user.pre_*` and `grant.pre_assign` defaults) **denies** the operation.
///
/// The third bullet is a loud, audited, per-tenant consequence of registering
/// a reactor that cannot be reached, and it is the safe direction. It is also
/// why [`Self::can_dispatch`] answers `false`: the REST layer refuses the
/// registration outright rather than letting an operator arm that outage
/// (SEC-101).
///
/// # This is no longer what `axiam-server` composes
///
/// R2.4 merged [`crate::reactor::transport::LapinReactorTransport`], and
/// `axiam-server` composes that. This type remains the correct transport for a
/// build assembled without a broker, and it is what the SEC-101 handler tests
/// exercise. Note the deliberate difference from a *disconnected* lapin
/// transport, which reports `can_dispatch() == true`: that one is a working
/// transport whose broker is momentarily away, and refusing registrations for
/// the duration of a broker blip would turn an outage into a second outage.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableReactorTransport;

/// The failure text a dispatch through [`UnavailableReactorTransport`] carries
/// into the audit record. Named so an operator can grep for it, and distinct
/// from [`crate::reactor::transport::REACTOR_TRANSPORT_DISCONNECTED`] — "this
/// build has no broker" and "the broker is away right now" are different
/// operational problems and must not read the same in an audit trail.
pub const REACTOR_TRANSPORT_UNAVAILABLE: &str =
    "no AMQP reactor transport is composed in this build";

impl ReactorTransport for UnavailableReactorTransport {
    async fn round_trip(
        &self,
        _reactor: &Reactor,
        _event: &'static str,
        _correlation_id: Uuid,
        _payload: serde_json::Value,
        _timeout_ms: u32,
    ) -> Result<ReactorReply, DispatchFailure> {
        Err(DispatchFailure::Transport(
            REACTOR_TRANSPORT_UNAVAILABLE.to_string(),
        ))
    }

    async fn publish_listen(
        &self,
        _reactor: &Reactor,
        _event: &'static str,
        _payload: serde_json::Value,
    ) -> Result<(), DispatchFailure> {
        Err(DispatchFailure::Transport(
            REACTOR_TRANSPORT_UNAVAILABLE.to_string(),
        ))
    }

    /// SEC-101 — the one implementation that answers `false`.
    fn can_dispatch(&self) -> bool {
        false
    }
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
    /// The reactor whose *reply* produced a terminal `Deny`, when the outcome
    /// is `Deny` for that reason (§22.6 rule 1: deny short-circuits, so at
    /// most one reactor's reply is ever the cause).
    ///
    /// `None` for every other outcome, and also `None` when the deny came
    /// from resolving a *failure* through `failure_policy` (a timeout, a
    /// rejected reply, a budget exhaustion) rather than from a genuine
    /// `decision: "deny"` reply — that reactor is already attributed via
    /// [`Self::failures`], which is where a health panel should count it.
    /// Conflating the two would double-count one denial as both a veto and a
    /// failure.
    ///
    /// R2.3: this is what lets the admin health surface attribute a "recent
    /// veto" to the specific reactor that issued it, rather than only to the
    /// chain as a whole.
    pub denied_by: Option<Uuid>,
}

/// Resolve one reactor's failure through its policy.
///
/// Public because the gate resolves two failures the chain never sees — the
/// per-tenant cap breach and an unreadable registry — and both must land on
/// exactly this function rather than on a second copy of the same `match`.
/// "No usable reply" is one closed set with one resolution; a second
/// implementation of it is a second place for `fail_closed` to quietly become
/// `fail_open`.
pub fn resolve_failure(policy: FailurePolicy, failure: &DispatchFailure) -> ReactorOutcome {
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
            denied_by: None,
        };
    };

    for reactor in reactors.iter().filter(|r| r.mode == ReactorMode::Intercept) {
        let spent = elapsed_ms();
        let remaining = MAX_CHAIN_BUDGET_MS.saturating_sub(spent);
        if remaining == 0 {
            let failure = DispatchFailure::BudgetExhausted;
            let outcome = resolve_failure(reactor.failure_policy, &failure);
            failures.push((reactor.id, failure));
            if let ReactorOutcome::Deny { reason } = outcome {
                // A budget-exhaustion deny is a *failure* resolved through
                // policy, not a reply — already attributed via `failures`
                // above, so `denied_by` stays `None` (see its doc comment).
                return ChainResult {
                    outcome: ReactorOutcome::Deny { reason },
                    failures,
                    denied_by: None,
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
                // A genuine `decision: "deny"` reply — the only case
                // `denied_by` is populated for.
                return ChainResult {
                    outcome: ReactorOutcome::Deny { reason },
                    failures,
                    denied_by: Some(reactor.id),
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
                let outcome = resolve_failure(reactor.failure_policy, &failure);
                failures.push((reactor.id, failure));
                if let ReactorOutcome::Deny { reason } = outcome {
                    // Failure-resolved, not reply-resolved — already
                    // attributed via `failures`.
                    return ChainResult {
                        outcome: ReactorOutcome::Deny { reason },
                        failures,
                        denied_by: None,
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

    ChainResult {
        outcome,
        failures,
        denied_by: None,
    }
}

/// A gate that runs no reactors, used when the feature is off.
///
/// Re-exported from `axiam-core` rather than defined here. It used to live in
/// this file, which meant the crates that must not know a broker exists could
/// not name the gate they are built with — the type that represents *"no
/// broker"* cannot itself live in the broker crate. It is now
/// [`axiam_core::models::reactor::NoopReactorGate`] and this alias exists so
/// `axiam_amqp::NoopReactorGate` keeps resolving.
pub use axiam_core::models::reactor::NoopReactorGate;

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

    /// [`Self::try_enter`], with a permit that does not borrow the limiter.
    ///
    /// The gate looks its limiter up in a per-tenant map and cannot hold a
    /// borrow into that map across the `await` that runs the chain. Same
    /// non-blocking acquire, same immediate `Overloaded`; only the permit's
    /// lifetime differs.
    pub fn try_enter_owned(&self) -> Result<tokio::sync::OwnedSemaphorePermit, DispatchFailure> {
        Arc::clone(&self.permits)
            .try_acquire_owned()
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
        let first_id = first.id;
        let second = reactor("second", 2, FailurePolicy::FailOpen, 500);
        let t = Scripted::new(vec![("first", deny()), ("second", allow())]);

        let result = run(&t, &[first, second]).await;
        assert!(!result.outcome.permits());
        assert_eq!(
            t.calls(),
            vec!["first"],
            "nothing later can overturn a deny, so nothing later should be asked"
        );
        // R2.3: a reply-driven deny is attributed to the reactor that issued
        // it, so a health panel can count "recent vetoes" per reactor.
        assert_eq!(result.denied_by, Some(first_id));
    }

    /// A deny resolved through `failure_policy` (a timeout, a rejected reply,
    /// a budget exhaustion) is a *failure*, not a veto — it must not be
    /// attributed via `denied_by`, or a health panel would double-count it as
    /// both a failure and a veto.
    #[tokio::test]
    async fn a_failure_resolved_deny_is_not_attributed_as_denied_by() {
        let r = reactor("fraud-check", 1, FailurePolicy::FailClosed, 500);
        let t = Scripted::new(vec![("fraud-check", Step::Fail(DispatchFailure::Timeout))]);

        let result = run(&t, &[r]).await;
        assert!(!result.outcome.permits());
        assert_eq!(
            result.denied_by, None,
            "a timeout resolved to a deny is a failure, already attributed via `failures`"
        );
    }

    #[tokio::test]
    async fn a_budget_exhausted_deny_is_not_attributed_as_denied_by() {
        let lenient = reactor("lenient", 1, FailurePolicy::FailOpen, 500);
        let veto = reactor("veto", 2, FailurePolicy::FailClosed, 500);
        let t = Scripted::new(vec![("lenient", allow()), ("veto", allow())]);

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

        assert!(!result.outcome.permits());
        assert_eq!(result.denied_by, None);
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
    fn the_owned_permit_bounds_the_same_way_as_the_borrowed_one() {
        let limiter = InFlightLimiter::new(1);
        let held = limiter.try_enter_owned().expect("first permit");
        assert_eq!(
            limiter.try_enter_owned().unwrap_err(),
            DispatchFailure::Overloaded
        );
        drop(held);
        assert!(
            limiter.try_enter_owned().is_ok(),
            "the permit must be returned when the dispatch finishes"
        );
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
                resolve_failure(FailurePolicy::FailOpen, &failure),
                ReactorOutcome::Allow
            );
            assert!(!resolve_failure(FailurePolicy::FailClosed, &failure).permits());
        }
    }
}

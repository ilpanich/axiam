//! R5.3 (X2 test gap) — property test: an RPT can never carry a
//! `(resource, scope)` pair the live engine would deny at mint time.
//!
//! `UmaService::exchange_ticket` (`crates/axiam-oauth2/src/uma.rs`) already has
//! unit tests pinning this for a handful of hand-picked scenarios (allow,
//! deny-override, partial-grant-is-refused-not-trimmed, ...). What is missing
//! is a proof over the *space* of possible grant tables, not a sample of it —
//! in particular the deny-adjacent corners: a pair with both an allow and a
//! deny grant (deny-override must still win), a pair with only a deny, a
//! ticket mixing allowed and denied pairs on the same resource, and multiple
//! resources with independently-random grant tables in the same ticket.
//!
//! # Why this is not a tautology
//!
//! `exchange_ticket` is "allow the whole ticket or refuse the whole ticket" —
//! it never trims a partially-allowed set (see the design note in `uma.rs`).
//! That makes "every pair in a *successful* RPT is allowed" true almost by
//! construction *if* the loop that walks `ticket.requested_pairs()` and the
//! lookup key it builds are both correct. What this test actually stresses is
//! that construction: a resource-id/scope mismatch in the lookup key, an
//! off-by-one in which pairs get iterated, or a short-circuit that stops
//! evaluating (and so misses a later deny) would all still let
//! `exchange_ticket` return `Ok` with a bad pair inside — and this is the test
//! that would catch it, by generating grant tables where most of the
//! interesting signal is in pairs that are *not* uniformly allowed, and by
//! re-deriving the ground truth from a **fresh** engine instance rather than
//! trusting the one `UmaService` already called.
//!
//! # The "seeded engine"
//!
//! [`SeededEngine`] is a `PermissionEvaluator` + `ScopeCatalog` built entirely
//! from a proptest-generated [`World`] — a deny-override truth table over a
//! random set of resources and scopes. proptest is itself deterministically
//! seeded per run (and persists the seed of any failing case to
//! `proptest-regressions/`), so "seeded" describes the whole engine: its
//! grant table is a pure function of the seed proptest drew, not of
//! wall-clock randomness, which is what makes a failure reproducible.
//!
//! `axiam-oauth2` does not depend on `axiam-authz` (see `uma.rs`'s module
//! docs), so `SeededEngine` models exactly the one axis `UmaService` itself
//! evaluates per pair — "does at least one explicit deny grant match" beats
//! "does at least one allow grant match" (B1 / SEC-040 deny-override) — and
//! does not attempt to model resource-hierarchy cascade, which is
//! `axiam-authz`'s concern and is proved separately there.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use axiam_core::error::AxiamResult;
use axiam_core::models::uma::{CreatePermissionTicket, PermissionTicket, RequestedPermission};
use axiam_core::repository::PermissionTicketRepository;
use axiam_oauth2::uma::{PairOutcome, PermissionEvaluator, ScopeCatalog, UmaService};
use chrono::Utc;
use proptest::prelude::*;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// An in-memory ticket store — the same shape as `uma.rs`'s private test fake,
// reimplemented here because that one is not exported (it lives in a
// `#[cfg(test)] mod tests` block, correctly private to unit tests).
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FakeTickets {
    rows: Mutex<Vec<PermissionTicket>>,
}

impl PermissionTicketRepository for FakeTickets {
    async fn create(&self, input: CreatePermissionTicket) -> AxiamResult<PermissionTicket> {
        let t = PermissionTicket {
            id: Uuid::new_v4(),
            tenant_id: input.tenant_id,
            ticket_hash: input.ticket_hash,
            client_id: input.client_id,
            permissions: input.permissions,
            consumed: false,
            expires_at: input.expires_at,
            created_at: Utc::now(),
        };
        self.rows.lock().unwrap().push(t.clone());
        Ok(t)
    }

    async fn consume(
        &self,
        tenant_id: Uuid,
        ticket_hash: &str,
        client_id: &str,
    ) -> AxiamResult<Option<PermissionTicket>> {
        let mut rows = self.rows.lock().unwrap();
        let now = Utc::now();
        for row in rows.iter_mut() {
            if row.tenant_id == tenant_id
                && row.ticket_hash == ticket_hash
                && row.client_id == client_id
                && !row.consumed
                && row.expires_at > now
            {
                let before = row.clone();
                row.consumed = true;
                return Ok(Some(before));
            }
        }
        Ok(None)
    }

    async fn find_by_hash(
        &self,
        tenant_id: Uuid,
        ticket_hash: &str,
    ) -> AxiamResult<Option<PermissionTicket>> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.tenant_id == tenant_id && r.ticket_hash == ticket_hash)
            .cloned())
    }

    async fn cleanup_expired(&self, _tenant_id: Uuid) -> AxiamResult<u64> {
        Ok(0)
    }
}

// ---------------------------------------------------------------------------
// The seeded engine: a proptest-generated deny-override truth table.
// ---------------------------------------------------------------------------

/// What grants exist for one `(resource, scope)` pair, before deny-override
/// resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PairTruth {
    /// No grant at all — default-deny.
    NoGrant,
    /// One or more allow grants, no deny.
    AllowOnly,
    /// One or more deny grants, no allow.
    DenyOnly,
    /// Both an allow and a deny grant on the same pair — the exact collision
    /// deny-override exists to resolve, and the case a naive "any grant
    /// matched" evaluator would get wrong.
    Both,
}

impl PairTruth {
    /// The ground-truth outcome this pair resolves to, independent of and
    /// prior to anything `UmaService` does with it.
    fn resolve(self) -> PairOutcome {
        match self {
            PairTruth::NoGrant => PairOutcome::NoGrant,
            PairTruth::AllowOnly => PairOutcome::Allowed,
            // Deny-override: an explicit deny wins whether or not an allow is
            // also present (B1 / SEC-040).
            PairTruth::DenyOnly | PairTruth::Both => PairOutcome::DeniedByRule,
        }
    }
}

/// One resource in the generated world: its id, its declared scopes (the
/// allow-list `ScopeCatalog` answers with), and the deny-override truth for
/// every declared scope.
#[derive(Debug, Clone)]
struct ResourceWorld {
    id: Uuid,
    declared: Vec<String>,
    truth: HashMap<String, PairTruth>,
}

/// A whole generated fixture: N resources, each with its own independently
/// random grant table.
#[derive(Debug, Clone)]
struct World {
    resources: Vec<ResourceWorld>,
}

/// `PermissionEvaluator` + `ScopeCatalog` over a [`World`]. This is the
/// "live engine" the property is checked against — every RPT permission that
/// survives `UmaService::exchange_ticket` must resolve `Allowed` here.
struct SeededEngine {
    world: World,
}

impl SeededEngine {
    fn new(world: World) -> Self {
        Self { world }
    }

    /// The ground truth for a pair — the same table `evaluate` reads,
    /// exposed so the property assertion can check an RPT's contents against
    /// a **fresh** instance rather than trusting the one `UmaService` called.
    fn ground_truth(&self, resource_id: Uuid, scope: &str) -> PairOutcome {
        self.world
            .resources
            .iter()
            .find(|r| r.id == resource_id)
            .and_then(|r| r.truth.get(scope))
            .map(|t| t.resolve())
            .unwrap_or(PairOutcome::NoGrant)
    }
}

impl PermissionEvaluator for SeededEngine {
    fn evaluate<'a>(
        &'a self,
        _tenant_id: Uuid,
        _subject_id: Uuid,
        resource_id: Uuid,
        scope: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<PairOutcome, String>> + Send + 'a>> {
        let outcome = self.ground_truth(resource_id, scope);
        Box::pin(async move { Ok(outcome) })
    }
}

impl ScopeCatalog for SeededEngine {
    fn declared_scopes<'a>(
        &'a self,
        _tenant_id: Uuid,
        resource_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>> {
        let scopes = self
            .world
            .resources
            .iter()
            .find(|r| r.id == resource_id)
            .map(|r| r.declared.clone())
            .unwrap_or_default();
        Box::pin(async move { Ok(scopes) })
    }
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

/// A deliberately small, named scope pool. Small so proptest collisions (the
/// same scope declared/requested more than once across shrinking runs) are
/// common rather than incidental — that repetition is what exercises the
/// lookup path's correctness, not an accident of a huge random namespace.
const SCOPE_POOL: &[&str] = &["read", "write", "delete", "admin", "export", "share"];

/// One `(resource, scope)` pair's truth, weighted toward the deny-adjacent
/// cases (`DenyOnly` and `Both`) rather than the trivially-allowed case: the
/// value of this test is in the corners a hand-written unit test is unlikely
/// to enumerate, not in re-proving that an all-allow ticket mints.
fn pair_truth_strategy() -> impl Strategy<Value = PairTruth> {
    prop_oneof![
        1 => Just(PairTruth::NoGrant),
        2 => Just(PairTruth::AllowOnly),
        3 => Just(PairTruth::DenyOnly),
        3 => Just(PairTruth::Both),
    ]
}

/// One resource's declared-scope set (2 to 6 unique names, an ordered
/// sub-sequence of the pool) plus independently generated grant truth for
/// every declared scope. Ids are not assigned here — [`world_strategy`]
/// assigns one per element by position, which is what lets this run through
/// the uniform `prop::collection::vec` combinator (every element drawn from
/// the *same* strategy) instead of hand-rolling a heterogeneous per-index
/// strategy.
fn single_resource_strategy() -> impl Strategy<Value = (Vec<String>, HashMap<String, PairTruth>)> {
    proptest::sample::subsequence(SCOPE_POOL.to_vec(), 2..=SCOPE_POOL.len()).prop_flat_map(
        |declared: Vec<&'static str>| {
            let n = declared.len();
            proptest::collection::vec(pair_truth_strategy(), n).prop_map(move |truths| {
                let declared: Vec<String> = declared.iter().map(|s| s.to_string()).collect();
                let truth: HashMap<String, PairTruth> =
                    declared.iter().cloned().zip(truths).collect();
                (declared, truth)
            })
        },
    )
}

/// A whole world: 1-3 resources, each independently random.
fn world_strategy() -> impl Strategy<Value = World> {
    proptest::collection::vec(single_resource_strategy(), 1..=3).prop_map(|resources| World {
        resources: resources
            .into_iter()
            .enumerate()
            .map(|(i, (declared, truth))| ResourceWorld {
                // Deterministic, distinct per-resource id — the randomness
                // that matters is in the grant table and the request, not in
                // what the uuid bytes are.
                id: Uuid::from_u128(0xAB00_0000_0000_0000_0000_0000_0000_0000 + i as u128),
                declared,
                truth,
            })
            .collect(),
    })
}

/// Whether the resource named by `(id, declared)` is named in the ticket,
/// and if so with which non-empty subset of its declared scopes.
///
/// Takes owned data rather than `&ResourceWorld`: a borrowing signature would
/// have the returned opaque `impl Strategy` capture the borrow's lifetime
/// (Rust 2024's default `impl Trait` capture rules), which cannot satisfy the
/// `'static` bound `.boxed()` needs in [`requested_strategy`] below.
fn optional_request_strategy(
    id: Uuid,
    declared: Vec<String>,
) -> impl Strategy<Value = Option<RequestedPermission>> {
    let len = declared.len();
    (
        proptest::bool::ANY,
        proptest::sample::subsequence(declared, 1..=len),
    )
        .prop_map(move |(include, scopes)| {
            include.then_some(RequestedPermission {
                resource_id: id,
                resource_scopes: scopes,
            })
        })
}

/// If every per-resource draw came back `None` (every resource excluded),
/// fall back to naming resource 0 with all its declared scopes — so every
/// generated case produces an actual, mintable ticket instead of a
/// vacuously-skipped empty one.
fn ensure_nonempty(
    options: Vec<Option<RequestedPermission>>,
    resources: &[ResourceWorld],
) -> Vec<RequestedPermission> {
    let mut v: Vec<RequestedPermission> = options.into_iter().flatten().collect();
    if v.is_empty() {
        let r = &resources[0];
        v.push(RequestedPermission {
            resource_id: r.id,
            resource_scopes: r.declared.clone(),
        });
    }
    v
}

/// The requested ticket for a fixed, already-generated `World`. Resource
/// count is 1-3 (fixed by `world_strategy`), so this is written as a
/// fixed-arity match over that count rather than a dynamically-sized
/// collection of heterogeneous per-resource strategies — every branch is
/// `.boxed()` into the same `BoxedStrategy` so the match arms unify.
fn requested_strategy(world: World) -> impl Strategy<Value = (World, Vec<RequestedPermission>)> {
    let resources = world.resources.clone();
    match resources.len() {
        1 => {
            let world = world.clone();
            optional_request_strategy(resources[0].id, resources[0].declared.clone())
                .prop_map(move |a| (world.clone(), ensure_nonempty(vec![a], &resources)))
                .boxed()
        }
        2 => {
            let world = world.clone();
            (
                optional_request_strategy(resources[0].id, resources[0].declared.clone()),
                optional_request_strategy(resources[1].id, resources[1].declared.clone()),
            )
                .prop_map(move |(a, b)| (world.clone(), ensure_nonempty(vec![a, b], &resources)))
                .boxed()
        }
        _ => {
            let world = world.clone();
            (
                optional_request_strategy(resources[0].id, resources[0].declared.clone()),
                optional_request_strategy(resources[1].id, resources[1].declared.clone()),
                optional_request_strategy(resources[2].id, resources[2].declared.clone()),
            )
                .prop_map(move |(a, b, c)| {
                    (world.clone(), ensure_nonempty(vec![a, b, c], &resources))
                })
                .boxed()
        }
    }
}

fn service(world: World) -> UmaService<FakeTickets, SeededEngine, SeededEngine> {
    // `SeededEngine` implements both ports; `UmaService` takes them as two
    // separate type parameters, so it needs two instances built from the same
    // world rather than one value shared by reference — matching the real
    // composition root, which wires two distinct implementations behind the
    // two traits.
    UmaService::new(
        FakeTickets::default(),
        SeededEngine::new(world.clone()),
        SeededEngine::new(world),
        3600,
    )
}

// ---------------------------------------------------------------------------
// The property
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        // Generous: the state space (grant truth x subset selection x up to
        // 3 resources) is large enough that the default 256 cases leaves
        // whole corners (e.g. 3-resource, all-`Both` tickets) rarely sampled.
        cases: 2000,
        ..ProptestConfig::default()
    })]

    /// The invariant: whatever `UmaService::exchange_ticket` returns in an
    /// RPT, every `(resource_id, scope)` pair inside it resolves `Allowed`
    /// against the same engine the mint consulted. A pair the engine would
    /// deny — `NoGrant` or `DeniedByRule` — must never appear.
    #[test]
    fn rpt_never_carries_a_pair_the_engine_would_deny(
        (world, requested) in world_strategy().prop_flat_map(requested_strategy),
    ) {
        let svc = service(world.clone());
        let tenant = Uuid::new_v4();
        let subject = Uuid::new_v4();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let outcome = rt.block_on(async {
            let minted = match svc.request_ticket(tenant, "rs-1", requested.clone()).await {
                Ok(m) => m,
                // An undeclared/blank/duplicate scope refuses before a ticket
                // exists — no RPT, nothing to check. `requested_strategy`
                // only ever draws declared subsets, so this should not
                // trigger, but the property does not depend on that staying
                // true.
                Err(_) => return None,
            };

            svc.exchange_ticket(tenant, "rs-1", &minted.ticket, subject, 3600)
                .await
                .ok()
        });

        // Re-derive ground truth from a fresh engine instance — independent
        // of the one `UmaService` actually consulted — so this checks the
        // RPT's *contents*, not merely that `evaluate` was called.
        let checker = SeededEngine::new(world);

        let any_pair_deniable = requested.iter().any(|p| {
            p.resource_scopes
                .iter()
                .any(|s| checker.ground_truth(p.resource_id, s) != PairOutcome::Allowed)
        });

        match outcome {
            Some(granted) => {
                for perm in &granted.permissions {
                    for scope in &perm.resource_scopes {
                        let truth = checker.ground_truth(perm.resource_id, scope);
                        prop_assert_eq!(
                            truth.clone(),
                            PairOutcome::Allowed,
                            "RPT carries ({}, {}) which the engine resolves to {:?}, not Allowed",
                            perm.resource_id,
                            scope,
                            truth,
                        );
                    }
                }
                // v1 refuses a partially-allowed ticket whole rather than
                // trimming it (see uma.rs's design note) — so a successful
                // mint is itself proof that nothing requested was deniable.
                prop_assert!(
                    !any_pair_deniable,
                    "ticket named a deniable pair but still minted an RPT"
                );
            }
            None => {
                // A refusal on its own proves nothing about this property
                // (it could also be e.g. an expired-subject refusal, not
                // exercised here since `subject_remaining_secs` is fixed at
                // 3600) — the meaningful assertion is the one above, checked
                // whenever an RPT *is* minted.
            }
        }
    }
}

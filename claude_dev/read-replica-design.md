# Read-replica design — routing hot authorization and identity reads off the primary

> A3/J11, from `claude_dev/improvement-after-run5-benchmark.md`.
> Status: **design approved, routing primitive implemented behind config;
> replica connection wiring and the §12.6 re-run are the remaining work.**
> Companion to `claude_dev/decision-cache-decision.md` (the other staleness
> contract in this system) and `claude_dev/db-pool-design.md`.

## 1. The measurement this exists to answer

Run 5's cache-off authorization cells:

| Cell | Datastore cores | Checks/s |
|---|---|---|
| authz check, cache off | 2 | 1 010 |
| authz batch, cache off | 2 | 1 032 |
| authz check, cache off, uncapped DB | 4 | **+75 %** |
| authz batch, cache off, uncapped DB | 4 | **+79 %** |

Giving the datastore twice the cores bought ~78 % more checks with no code
change. That is the signature of a **concurrency** ceiling, not a per-query
cost one — and it is the reason this work now outranks further query tuning.
The hot authorization queries are already index-backed and CI-guarded against
table scans; making each one cheaper does not move a number that is set by how
many of them can be in flight at once.

There are two ways to raise a concurrency ceiling: give the primary more of the
machine (CP-3, §6 below) or stop sending it reads it does not need to serve.
This document is the second.

## 2. What gets routed, and what never does

The classification lives in code (`crates/axiam-db/src/read_preference.rs`,
`QueryClass`) rather than in this document, so that it is enforced rather than
merely described. Restated here for review:

| Query class | Routing | Why |
|---|---|---|
| `AuthzDecision` — role/permission/resource reads behind a check | **replica-eligible** | The ceiling run 5 measured. Already served behind a TTL decision cache, so this data's staleness is already an accepted property of the deployment. |
| `IdentityRead` — userinfo, profile lookups | **replica-eligible** | A profile field arriving late is a display concern, not an access-control one. |
| `PublicKeyMaterial` — JWKS | **replica-eligible** | Rotation publishes the new key *before* retiring the old one, so a lagging replica serves a valid superset, never a gap. |
| `SessionRevocation` — session validity, token revocation | **primary, always** | Logout is what an operator reaches for when something has gone wrong. "It takes effect once the replica catches up" is not an acceptable answer to that. |
| `WritePath` — any read taken in order to write | **primary, always** | Read-modify-write against a replica is a lost update, not a staleness trade. |

`ReadPreference::default()` is `Primary`. A call site nobody has classified is
therefore correct by omission — the failure mode of forgetting is a slower
query, never a staler one.

## 3. The staleness contract

This is the security-relevant part of the design, and it is deliberately
written to mirror the decision cache's contract rather than to invent a second
vocabulary for the same idea.

|  | Decision cache | Read replica |
|---|---|---|
| Bound on staleness | TTL, **plus** event-path invalidation | replication lag |
| Measured | 262 ms event-path deny (run 5) | to be measured — see §7 |
| Worst case | a grant revoked *out of band* is honoured until TTL expiry | a grant revoked on the primary is honoured until the replica catches up |
| Bounded by | something the server controls (it fires the invalidation) | something the datastore controls (the replica's own progress) |
| Never stale | anything on the event path | anything routed `Primary` |

**A replica-lag allow is the same class of stale allow as a cache-TTL allow.**
That sentence is the whole contract. A deployment that has enabled the decision
cache has already accepted this shape of risk and gains a second instance of
it; a deployment that has not enabled the cache should not enable replicas
either. Both default to off.

One asymmetry is worth stating plainly rather than glossing: the cache's bound
is enforced by AXIAM (it fires invalidation on the event path, and the 262 ms
is *measured*), whereas replica lag is bounded only by the replica's own
progress and AXIAM cannot observe it per query. `AXIAM__DB__READ_REPLICA_MAX_STALENESS_MS`
therefore **declares** a bound rather than enforcing one: it documents what the
deployment is accepting and tells the operator what to alert on. An unstated
staleness bound is an unbounded one, which is why the value exists at all.

### Denies are not affected the way allows are

A revocation that has not yet reached a replica produces a **stale allow** —
the dangerous direction. The reverse (a *grant* that has not yet reached a
replica producing a spurious deny) is a correctness annoyance, not a security
event, and it self-heals within the lag window. Any deployment where the
spurious-deny direction matters (provisioning a user and immediately acting as
them) should read `AuthzDecision` from the primary; that is the
"reads-your-own-writes is not guaranteed" note the SDK contract carries for the
client-side decision memo, and it applies here identically.

## 4. Failure modes

| Failure | Behaviour | Rationale |
|---|---|---|
| No replicas configured | every read → primary | the shipped default; the feature is inert |
| Replica unreachable / connection evicted | that read → primary | **never fail closed on a read.** A read path must not start erroring because a *performance* optimisation is unavailable. The worst a replica outage may cost is the throughput the replica was adding. |
| Replica lagging beyond the declared bound | still served (see caveat) | AXIAM cannot see per-query lag; this is why the bound is declared and alerted on rather than enforced. Operators who need enforcement should remove the replica from the list, which is a config change, not a code change. |
| All replicas down | every read → primary, at pre-replica throughput | degrades to exactly today's behaviour |
| Primary down | reads that are replica-eligible may still succeed; writes fail | not a designed HA story — do not read this row as one. It is a note that the degradation is uneven. |

## 5. Configuration

```bash
# Off by default. Empty or unset = every read goes to the primary.
AXIAM__DB__READ_REPLICAS=ws://surrealdb-replica-0:8000,ws://surrealdb-replica-1:8000

# Declared (not enforced) staleness bound for replica-eligible reads.
# Default 500 ms — same order of magnitude as the decision cache's measured
# 262 ms event-path invalidation, so an operator reasoning about "how stale can
# an allow be" gets one answer rather than two unrelated ones.
AXIAM__DB__READ_REPLICA_MAX_STALENESS_MS=500
```

No API changes. No changes to any repository method signature: routing is
resolved inside `DbHandle::current_for(ReadPreference)`, which sits exactly
where `DbHandle::current()` already did, so a repository opts a query in by
naming its class and nothing else changes.

Replicas are round-robined, with the cursor shared across every clone of the
handle — every repository holds a clone of one handle, so the spread is
process-wide rather than per-repository.

## 6. CP-3: tune the primary first

Replicas are the larger change; the cheaper one is to stop under-serving the
primary. The CP-3 sweep (SurrealDB worker threads, connection-pool size per
`claude_dev/db-pool-design.md`, memory limits, at 2c and 4c) belongs **before**
a replica rollout, because a primary that is merely mis-tuned will present the
same +75 % headroom that replicas would, at none of the staleness cost.

**Status: not run.** The sweep needs the G-box benchmark harness (a two-node
matrix with pinned datastore cores) and cannot be produced in a development
sandbox; producing a knob→throughput table from an unrepresentative machine
would be worse than having no table, because it would be quoted. The runbook
entry and the table skeleton are in
`claude_dev/surrealdb-tuning-report.md` (run-5 section) awaiting a real pass.

## 7. Proving it — the bench plan

Re-run the §12.6 authorization matrix with one replica attached:

| Cell | Purpose |
|---|---|
| authz check, cache off, 0 replicas | baseline (= run 5's 1 010/s) |
| authz check, cache off, 1 replica | the headline claim |
| authz check, cache on, 1 replica | the shipped-posture number |
| authz batch, cache off, 1 replica | batch amplification |
| **lag probe** | write a grant on the primary, poll a replica-routed check until it flips; report p50/p95/max. This is the number that turns §3's *declared* bound into a *measured* one, and it is the cell that must exist before any replica claim is published. |

Acceptance for shipping the feature on: the lag probe's p95 is inside the
declared bound, primary-pinned classes are provably never replica-routed (unit
tests already assert this), and no headline run-5 cell regresses.

## 8. Deployment

`k8s/` gains a replica StatefulSet and a read-only Service; the network policy
allows server→replica on the datastore port. Compose gains an equivalent
optional replica service. Both are additive: a deployment that does not set
`AXIAM__DB__READ_REPLICAS` behaves exactly as it does today.

Operator documentation must state §3's contract in the operator's own terms —
"revocation is not affected; authorization grants may lag by up to N ms" — not
in terms of `QueryClass` names.

## 9. What this design deliberately does not do

- **No automatic failback on measured lag.** AXIAM cannot see per-query lag,
  and a heuristic that guessed at it would be a security control built on a
  guess.
- **No per-tenant replica routing.** A tenant-level staleness policy is a
  bigger contract (it would need to appear in the tenant config API and in
  every SDK) and there is no evidence yet that anyone needs it.
- **No read-your-own-writes session pinning.** Deferred until the lag probe
  says whether it is needed; the honest interim answer is the documented
  "reads-your-own-writes is not guaranteed" note.

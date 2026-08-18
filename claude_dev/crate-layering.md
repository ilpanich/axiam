# Crate layering — the dependency rule, and the gate that holds it

**Status:** enforced in CI (`scripts/check-crate-layering.py`, job `Architecture Invariants`)
**Introduced by:** the 2026-08 SOLID / clean-architecture review, finding F1

## The rule

Layers are numbered outward from the domain. **A crate may depend only on crates
in a strictly lower layer.** Dependencies point inward, toward the domain, never
outward.

| Layer | Name | Crates |
|---:|---|---|
| 0 | domain | `axiam-core`, `axiam-test-support` |
| 1 | domain services | `axiam-auth`, `axiam-authz`, `axiam-pki`, `axiam-email` |
| 2 | infrastructure | `axiam-db`, `axiam-audit` |
| 3 | federation protocol | `axiam-federation` |
| 4 | authorization server | `axiam-oauth2` |
| 5 | messaging adapter | `axiam-amqp` |
| 6 | protocol adapters | `axiam-api-rest`, `axiam-api-grpc` |
| 7 | REST sub-surface | `axiam-scim` |
| 8 | composition root | `axiam-server` |

`scripts/check-crate-layering.py --graph` prints this table with every crate's
actual edges resolved against it, which is the authoritative version — this
document is a summary and the script is the gate.

## Why these layers and not others

**`axiam-core` is layer 0 and has no dependencies, ever.** It holds the entities
and the repository *ports* (46 traits, 262 methods, segregated per aggregate).
Everything else is an implementation of, or a consumer of, something declared
there.

**`axiam-db` at layer 2 depending on `axiam-auth` and `axiam-pki` at layer 1 is
correct, not a violation.** This edge looks wrong at a glance — infrastructure
reaching for a domain service — and the review that produced this gate initially
flagged it. Under the dependency rule it is exactly right: the adapter is the
outer ring and it reaches *inward*. Password hashing belongs next to the write
(`repository/user.rs` delegates to `axiam_auth::password`), and the alternative —
re-implementing Argon2id inside `axiam-db` so the graph looks tidier — would be
the actual mistake.

**`axiam-federation` and `axiam-oauth2` are two layers, not one.** `axiam-oauth2`
consumes `axiam-federation`; splitting them makes the reverse edge impossible
rather than merely absent.

**`axiam-scim` sits above `axiam-api-rest` rather than beside it.** SCIM is a REST
sub-surface mounted into the same Actix app: it consumes the REST crate's
`AppState` and extractors. One layer out records the invariant that matters —
SCIM may use REST, REST may never use SCIM.

## Dev-dependencies may invert, but must be named

Three crates reach *outward* in `[dev-dependencies]` only:

| Edge | Why |
|---|---|
| `axiam-auth` → `axiam-db` | `AuthService`'s tests exercise login, lockout and refresh rotation against real repositories, because the behaviour under test *is* the interaction with them |
| `axiam-authz` → `axiam-db` | the engine's tests seed real role/permission/resource rows; a hand-rolled double would encode this gate's assumptions about hierarchy traversal instead of testing them |
| `axiam-pki` → `axiam-db` | certificate-issuance tests persist and re-read the issued material to prove the private key is never stored |

The inversion never reaches a shipped artifact, because `[dev-dependencies]` do
not. It is still declared in `TEST_ONLY_INVERSIONS`, for one reason: an
undeclared test-only inversion is how a "temporary" helper becomes a production
import. Somebody moves one function out of `#[cfg(test)]` and the edge promotes
itself silently. A named exemption gets reviewed; an implicit one does not.

## What the gate reports

| Situation | Result |
|---|---|
| production edge to an equal or outer layer | fail, naming both layers |
| `build-dependencies` edge to an equal or outer layer | fail (a build script is production) |
| undeclared outward `dev-dependencies` edge | fail, with the exact `TEST_ONLY_INVERSIONS` entry to add |
| a workspace crate absent from the layer table | fail — an unplaced crate has no rule to violate, which is the one state that must never read as healthy |
| a layer-table entry with no crate behind it | fail — a stale exemption reads as precedent |
| gate cannot run (no `crates/`, unparseable TOML) | exit 2, deliberately *not* exit 0 |

Both `{ workspace = true }` and `{ path = "…" }` forms are picked up, as are
platform-gated `[target.'cfg(…)'.dependencies]` tables. All three have been used
in this workspace and all three create an edge.

## Running it

```console
$ scripts/check-crate-layering.py
Crate layering OK: 15 crates, 50 internal production edge(s), all pointing inward;
3 declared test-only inversion(s).

$ scripts/check-crate-layering.py --graph      # the table, with resolved edges
$ scripts/check-crate-layering.py --self-test  # the gate's own fixtures
```

The self-test runs on fixtures rather than on the workspace, and runs **first** in
CI. A gate whose only evidence is "the repo it guards is currently clean" cannot
tell working from broken: a check script with an inverted comparison passes every
day until the day it matters.

## Changing the layering

Moving a crate between layers is a design decision, so it is a reviewable diff in
`scripts/check-crate-layering.py` rather than a config value. When the gate fails,
exactly one of two things is true — the edge is wrong, or the table is. Both are
fine outcomes; defaulting to neither is not.

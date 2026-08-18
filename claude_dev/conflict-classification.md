# Conflict classification — one definition of "already exists"

**Status:** enforced in CI (`scripts/check-conflict-markers.py`, job `Architecture Invariants`)
**Introduced by:** the 2026-08 SOLID / clean-architecture review, finding F5
**Supersedes the honour-system half of:** D-09

## The problem

SurrealDB reports a UNIQUE-index violation as free text:

```
Database index `idx_replay_uniq` already contains ['t1', 'assertion-1'],
with record `saml_assertion_replay:abc`
```

There is no typed variant to match on, so deciding "was this a conflict?" means
matching substrings. Three markers do it: `already contains`, `already exists`,
`unique`.

**That match is a security outcome.** At the three replay guards it is the
difference between refusing a replayed SAML assertion / AMQP nonce / DPoP proof
and accepting it as fresh. At the bootstrap handler it is the difference between
one administrator and a race for the first one.

## What was wrong

`axiam_db::helpers::classify_write_error` has carried this sentence since D-09:

> Per D-09, this is the ONLY place that inspects error text for these markers —
> call sites must not add their own inline `contains(...)` checks.

Five sites did anyway, with the three markers written out again in each:

| Site | Conflict means |
|---|---|
| `axiam-db/src/repository/saml_replay.rs` | replayed SAML assertion |
| `axiam-db/src/repository/amqp_nonce_replay.rs` | replayed AMQP message |
| `axiam-db/src/repository/oauth2_proof_replay.rs` | replayed DPoP proof / client assertion `jti` |
| `axiam-db/src/repository/federation_login_state.rs` | duplicate SSO `state` |
| `axiam-api-rest/src/handlers/bootstrap.rs` | deployment already initialised |

None of it was careless. The copies were kept deliberately identical, and
`oauth2_proof_replay` said so:

> kept identical so the three replay guards cannot drift into disagreeing about
> what a conflict looks like.

That is exactly the right worry and exactly the wrong mechanism. A new marker —
say a SurrealDB v4 message that phrases the violation differently — applied to
four of the five sites is a security fix with a hole in it, and **nothing in the
test suite or CI would have failed.**

## What it is now

The markers live in `axiam_db::helpers`, once:

```rust
const UNIQUE_VIOLATION_MARKERS: [&str; 3] = ["already contains", "already exists", "unique"];

pub fn is_unique_violation(msg: &str) -> bool
```

and three classifiers wrap it, one per meaning a conflict can carry:

| Classifier | Conflict → | Anything else → |
|---|---|---|
| `classify_replay_write_error(err)` | `AxiamError::ReplayDetected` | `AxiamError::Database` (5xx) |
| `classify_conflict_write_error(err, entity)` | `AxiamError::AlreadyExists` (409) | `AxiamError::Database` (5xx) |
| `classify_write_error(err, entity)` | `DbError::AlreadyExists` (409) | `DbError::Migration` (5xx) |

A call site that needs to keep its own non-conflict error context — the
bootstrap handler wants a `"bootstrap transaction: …"` prefix in the server log
— calls `is_unique_violation` directly. That is fine and gated: the rule is
about the *markers*, not about which wrapper you use.

## Why the marker set stays narrow

Everything `is_unique_violation` does not match falls through to a 5xx, and that
is the safe direction. A datastore outage contains none of these markers, so it
surfaces as "the database is unavailable" rather than as "that already exists"
(a false 409) or "that was a replay" (a false refusal of legitimate traffic).

Widening the set trades a clearer conflict message for the risk of answering an
outage with a 409. Do not widen it without a real server message to point at —
and when you do, add that message to `REAL_VIOLATION_MESSAGES` in
`helpers.rs`'s test module, which quotes server output verbatim rather than
paraphrasing it. A paraphrase that happens to contain "already contains" passes
the test while proving nothing about what the server actually sends.

## The shared sweep

The three replay tables also carried a byte-identical `cleanup_expired`: count
the rows past `expires_at`, then delete them. That is now
`helpers::cleanup_expired_rows(&db, table)`.

It is not security-critical the way the classifier is — a sweep that
under-deletes leaves rows that only cost space, and the UNIQUE index keeps doing
its job regardless — but three copies of one query is three places to fix when
the count and the delete need to become a single statement.

`table` is interpolated rather than bound, because SurrealDB has no bind form
for a table name. It is therefore never caller- or request-derived: every call
site passes a `&'static str` literal naming one of this crate's own tables.

## The gate

`scripts/check-conflict-markers.py` fails CI if any `.rs` file outside
`crates/axiam-db/src/helpers.rs` contains one of the marker *literals* in
non-test code.

- It matches the Rust string literal (`"already exists"`), not the bare words,
  so prose in a doc comment is not a finding.
- `#[cfg(test)]` modules and files under `tests/` are exempt: a test asserting
  that a real server message classifies correctly has to quote that message,
  and that is the point of it.
- `--self-test` exercises the gate's own decisions on synthetic lines, and
  additionally asserts that the owner file still defines both the markers and
  `is_unique_violation` — a gate pointing at a file that no longer holds them is
  worse than no gate at all.

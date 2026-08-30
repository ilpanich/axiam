# Phase 13: SurrealDB Connection Resilience - Context

**Gathered:** 2026-06-19
**Status:** Ready for planning
**Source:** Direct authoring from the Phase-12 smoke debugging session (root cause reproduced and confirmed live)

<domain>
## Phase Boundary

Make `axiam-server`'s SurrealDB connection resilient so that an idle WebSocket
reconnect can never silently drop the `use_ns`/`use_db` selection and route
queries to the empty default namespace. Repair the documented local first-run
seed path so a working admin can be created end-to-end, which unblocks the
deferred Phase-12 manual smoke (`12-HUMAN-UAT.md`).

In scope: `crates/axiam-db/src/connection.rs` (`DbManager`), a reconnect
regression test, `scripts/e2e-bootstrap.sh` repair, and an optional
`just bootstrap-local` helper.

Out of scope: any change to repository query logic, the bootstrap handler, or
the Phase-12 remediation code (all verified correct — a fresh connection finds
correctly-seeded records).
</domain>

<decisions>
## Implementation Decisions

### Root cause (confirmed, locked)
- The server selects `ns=axiam`/`db=main` once at connect via `db.use_ns().use_db()`.
  After an idle WebSocket reconnect the SurrealDB Rust SDK does not replay that
  selection, so subsequent queries hit the default `main`/`main` (empty) namespace
  and return empty/"not found" with NO error. Proven: a fresh SDK connection finds
  the seeded org via the exact repo path; the long-running server does not; the
  SurrealDB container never restarted (`RestartCount=0`).

### Connection resilience (the durable fix)
- `DbManager` MUST guarantee the active namespace/database after any reconnect.
  Acceptable mechanisms (planner to choose the cleanest for surrealdb 3.0.0):
  re-issue `use_ns`/`use_db` on a reconnect signal, OR a lightweight pre-query/
  periodic guard that re-asserts ns/db, OR an SDK config that persists session
  selection across reconnect. Prefer the SDK-native mechanism if one exists.
- `health_check` MUST verify the connection is bound to the EXPECTED ns/db (e.g.
  assert via `INFO FOR DB` / a sentinel query against `ns=axiam`/`db=main`), not
  merely that the socket is alive — so a wrong-namespace connection is detected.
- A regression test MUST reproduce the failure: force/simulate a reconnect (or
  a new session that lost selection) and assert that a read of a known record
  still succeeds against the correct namespace.

### First-run seed repair (unblocks the smoke)
- `scripts/e2e-bootstrap.sh` writes to `surreal-db: axiam` but the server reads
  `db=main` (DbConfig default). Correct the script to target the same database
  the server uses (parameterize from `AXIAM__DB__*` / default `main`), and remove
  the `is_active` field from the tenant CREATE (the `tenant` table schema has no
  such field — it currently fails statement 2).
- Add a `just bootstrap-local` recipe that seeds org+tenant+admin against the
  `run-local` server (mirrors e2e-bootstrap but targets the local db and the
  public `/api/v1/admin/bootstrap` endpoint), so first-run is one command.

### Verification
- After the fix, the deferred 11-item smoke (`12-HUMAN-UAT.md`) is runnable; this
  phase does not itself execute the manual smoke but must make it executable.

### Claude's Discretion
- Exact SDK reconnect-hook vs. guard-query mechanism (research decides).
- Test harness for simulating a reconnect (may use a fresh session that never
  selected ns/db as a proxy for a reconnected-but-unselected connection).
</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Connection + repro
- `crates/axiam-db/src/connection.rs` — `DbManager::connect`/`health_check`; the ns/db selection site
- `crates/axiam-db/src/repository/organization.rs` — `get_by_id` (the query that returned "not found"); confirmed correct
- `crates/axiam-server/src/main.rs:677-695` — `load_config` + the bootstrap-time assertions; boot seeding at ~242-282

### First-run seed
- `scripts/e2e-bootstrap.sh` — org/tenant seed (db-name mismatch + `is_active` drift)
- `crates/axiam-db/src/schema.rs:155-179` — `organization`/`tenant` SCHEMAFULL field definitions
- `justfile` — `dev-up`, `run-local` (Phase-12 additions) for the local-dev pattern

### Deferred verification
- `.planning/phases/12-low-remediation/12-HUMAN-UAT.md` — the 11-item smoke this phase unblocks

### Project DB conventions
- SurrealDB v3 quirks live in the project auto-memory (record IDs via `type::record`,
  `SurrealValue` derive, `.check()` ownership, `/sql` per-statement status).
</canonical_refs>

<specifics>
## Specific Ideas

- The SurrealDB default ns/db is `main`/`main` (`INFO FOR ROOT` → `defaults`). A lost
  selection silently falls back there — the failure is invisible (empty results, no error).
- Disk near-full: build/test per-crate with `-p`, `--no-default-features`. The DB tests
  can use the live `just dev-up` SurrealDB or the in-memory `kv-mem` engine.
</specifics>

<deferred>
## Deferred Ideas

- Executing the 11-item manual smoke itself (tracked in `12-HUMAN-UAT.md`; run after this phase).
- Broader SDK upgrade or connection-pool changes beyond the reconnect-resilience fix.
</deferred>

---

*Phase: 13-surrealdb-connection-resilience*
*Context gathered: 2026-06-19 via direct authoring from the Phase-12 debugging session*

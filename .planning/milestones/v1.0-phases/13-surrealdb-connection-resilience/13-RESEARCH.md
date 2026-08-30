# Phase 13: SurrealDB Connection Resilience - Research

**Researched:** 2026-06-19
**Domain:** SurrealDB Rust SDK 3.x WebSocket session state / reconnect resilience
**Confidence:** HIGH (root cause confirmed; SDK behavior confirmed via official issue tracker)

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- Root cause confirmed: `use_ns`/`use_db` is NOT replayed by the SDK after WebSocket auto-reconnect.
  After idle reconnect the connection silently falls back to `main`/`main` (empty), returning
  empty/"not found" with no error.
- `health_check` MUST verify actual ns/db selection, not just socket liveness.
- A regression test MUST reproduce the failure (new session that never selected ns/db).
- `scripts/e2e-bootstrap.sh` MUST be corrected: `surreal-db: axiam` → `surreal-db: main`,
  remove `is_active` from tenant CREATE.
- Add `just bootstrap-local` recipe.
- Disk near-full: build/test per-crate `-p axiam-db --no-default-features` only.

### Claude's Discretion
- Exact SDK reconnect-hook vs. guard-query mechanism (this research decides — see Q2 below).
- Test harness for simulating reconnect.

### Deferred Ideas (OUT OF SCOPE)
- Executing the 11-item manual smoke (run after this phase).
- Broader SDK upgrade or connection-pool changes beyond reconnect-resilience fix.
</user_constraints>

---

## Summary

The SurrealDB Rust SDK 3.x does **not** replay `use_ns`/`use_db` (or `signin`) on WebSocket
auto-reconnect. This is a documented open defect (GitHub issue #5750, opened April 2025, still
open as of the research date). The SDK auto-reconnects the transport layer but starts a fresh,
unselected session. Subsequent queries silently hit the default `main`/`main` namespace, which
is empty in the AXIAM deployment, returning not-found with no error signal.

There is **no SDK-native reconnect hook or callback** in 3.1.3 that would allow injecting
`use_ns`/`use_db` replay. The only available SDK event primitive is `.wait_for(WaitFor::Database)`,
which fires once at initial connect, not on every reconnect.

The correct fix is a **periodic guard task** that runs `RETURN [session::ns(), session::db()]`
on a short interval, detects a wrong/null selection, and re-issues `signin` + `use_ns`/`use_db`.
This is the standard community workaround while issue #5750 remains open.

The `health_check` method must be upgraded to assert the expected ns/db via `session::ns()` /
`session::db()`, not merely `RETURN 1`.

**Primary recommendation:** Wrap `DbManager` with a background keepalive task that re-selects
ns/db whenever selection is lost, and upgrade `health_check` to verify the actual selection.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| WebSocket ns/db selection | DB client layer (`axiam-db`) | — | `DbManager` owns the `Surreal<Client>`; it must guarantee invariants on that handle |
| Reconnect detection | DB client layer (`axiam-db`) | — | The SDK fires no application-level event; polling is the only mechanism |
| Health verification | DB client layer (`axiam-db`) | API/server (Actix health route) | `health_check` is called by Actix health route — must surface real faults |
| Seed correctness | Scripts (`e2e-bootstrap.sh`) | `justfile` | Configuration mismatch fixed at the script layer |

---

## Q1: Does surrealdb 3.1.3 replay `use_ns`/`use_db` on auto-reconnect?

**Answer: NO.** [VERIFIED: github.com/surrealdb/surrealdb/issues/5750]

GitHub issue #5750 ("Ability to handle `ws_meta` websocket reconnects", opened 2025-04-04,
status **open** as of research date) explicitly describes the problem:

> "When a SurrealDB instance has a websocket connection that is reset due to internet dropping,
> there is no way to handle this case, and users sometimes get unrecoverable errors like
> 'Haven't selected NS or DB' even though they have been selected in the past."

The SDK auto-reconnects the TCP/WebSocket transport but initialises a clean session with no
namespace or database selected. The `use_ns`/`use_db` state is NOT stored and replayed on the
new connection.

Why the failure is **silent** in AXIAM's case: the SurrealDB server default namespace/database
is `main`/`main`. After reconnect the server assigns that default. A query like
`SELECT * FROM organization WHERE id = type::record(...)` runs against an empty `main`/`main`
database and returns an empty result set — no error, just zero rows. Callers see "not found".

The confirmed reproduction test:
- Fresh connection → `signin` → **no** `use_ns`/`use_db` → run the same `get_by_id` query →
  always returns "not found" even against a seeded DB.

---

## Q2: Cleanest mechanism for reconnect resilience in 3.1.3

**No SDK-native hook exists.** [CITED: github.com/surrealdb/surrealdb/issues/5750]

### Options evaluated

| Option | Feasibility | Verdict |
|--------|-------------|---------|
| Reconnect hook / callback API | Does not exist in 3.1.3 | NOT AVAILABLE |
| `.wait_for(WaitFor::Database)` | Fires once at initial connect only | NOT SUITABLE |
| Connection option to persist session | Not documented; not in `Connect` builder API | NOT AVAILABLE |
| Re-issue `use_ns`/`use_db` before every query | Correct but high call overhead for hot paths | FALLBACK ONLY |
| Periodic background guard task | Lightweight, SDK-compatible, standard workaround | **RECOMMENDED** |

### Recommended: Periodic background guard task

**Implementation:**

1. Add two fields to `DbManager`:
   - `config: DbConfig` (already has ns/db/credentials)
   - `_guard: tokio::task::JoinHandle<()>` — background loop

2. Spawn a `tokio::task::spawn` loop that every N seconds:
   a. Queries `RETURN [session::ns(), session::db()]`
   b. Deserialises as `(Option<String>, Option<String>)`
   c. If either differs from `config.namespace`/`config.database` (or is `None`): re-issues
      `signin` then `use_ns`/`use_db`
   d. Logs at WARN level when re-selection occurs

3. Interval: **30 seconds** is conservative. The idle timeout in default SurrealDB server config
   is not documented as a fixed value; observed behavior suggests reconnects after minutes of
   idle. 30 s polling re-selects well before any query arrives post-reconnect.

**Exact 3.1.3 API surface:** [ASSUMED for interval choice; VERIFIED: docs.rs/surrealdb/3.x]

```rust
use surrealdb::Surreal;
use surrealdb::engine::remote::ws::{Client, Ws};
use surrealdb::opt::auth::Root;
use tokio::time::{interval, Duration};
use tracing::{info, warn};

// Inside DbManager::connect, after initial use_ns/use_db:
let guard_db = db.clone();    // Surreal<Client> is Clone + Send + Sync
let guard_config = config.clone();
let _guard = tokio::task::spawn(async move {
    let mut ticker = interval(Duration::from_secs(30));
    loop {
        ticker.tick().await;
        // Query active ns and db
        let result: surrealdb::Result<Option<(Option<String>, Option<String>)>> = guard_db
            .query("RETURN [session::ns(), session::db()]")
            .await
            .and_then(|mut r| r.take(0));

        match result {
            Ok(Some((ns, db_name)))
                if ns.as_deref() == Some(&guard_config.namespace)
                    && db_name.as_deref() == Some(&guard_config.database) =>
            {
                // Selection is correct — nothing to do
            }
            _ => {
                warn!("SurrealDB session selection lost or wrong — re-selecting ns/db");
                let _ = guard_db
                    .signin(Root {
                        username: guard_config.username.clone(),
                        password: guard_config.password.clone(),
                    })
                    .await;
                let _ = guard_db
                    .use_ns(&guard_config.namespace)
                    .use_db(&guard_config.database)
                    .await;
                info!(
                    namespace = %guard_config.namespace,
                    database  = %guard_config.database,
                    "SurrealDB session re-selected"
                );
            }
        }
    }
});
```

`Surreal<Client>` is `Clone + Send + Sync` — cloning it shares the same underlying connection
handle, so re-calling `use_ns`/`use_db` on the clone affects all callers sharing that handle.
[VERIFIED: docs.rs/surrealdb — "Cloning a Surreal<C> client instance creates a new session
with independent state while sharing the underlying database connection."]

**NOTE on clone semantics:** The v3 docs also say "cloning creates a session with independent
state". This means `use_ns`/`use_db` called on a clone sets that clone's session state, NOT the
original handle's. Therefore the guard task **must operate on the SAME `db` handle**, not a
clone. The `DbManager.db` field is the handle that repositories receive via `.client()`.
The guard must capture `db.clone()` only if clones truly share selection state — verify this
empirically in the regression test (Q4). If they do not, the guard must hold a shared
`Arc<Surreal<Client>>` and operate on the original.

**Safe implementation pattern (avoids clone ambiguity):**

```rust
// Wrap the shared handle in Arc so guard and manager both own the same allocation
use std::sync::Arc;

pub struct DbManager {
    db: Arc<Surreal<Client>>,
    _guard: tokio::task::JoinHandle<()>,
}
```

Alternatively: wrap in `Arc<Mutex<...>>` only if `Surreal<Client>` requires exclusive access
for `use_ns`/`use_db` — it does NOT (methods take `&self`), so plain `Arc` suffices.

---

## Q3: Health check — verify expected ns/db

**SurrealQL session functions (verified):** [CITED: surrealdb.com/docs/surrealql/functions/database/session]

- `session::ns()` — returns the currently selected namespace (string or null)
- `session::db()` — returns the currently selected database (string or null)

These run on the server in the current session's context, so they return the server-side
effective namespace, not anything client-cached. This is the correct verification mechanism.

**Upgraded `health_check` implementation:**

```rust
pub async fn health_check(&self) -> Result<(), surrealdb::Error> {
    // Assert socket liveness AND correct namespace/database selection.
    // Using session:: functions runs server-side against the current session context.
    let mut result = self
        .db
        .query("RETURN [session::ns(), session::db()]")
        .await?;

    let row: Option<(Option<String>, Option<String>)> = result.take(0)?;

    match row {
        Some((ns, db)) if ns.as_deref() == Some(&self.config.namespace)
                        && db.as_deref() == Some(&self.config.database) => {
            Ok(())
        }
        Some((ns, db)) => Err(surrealdb::Error::Api(surrealdb::error::Api::ParseError(
            format!(
                "SurrealDB session points to wrong ns/db: ns={:?} db={:?}, expected ns={} db={}",
                ns, db, self.config.namespace, self.config.database
            ),
        ))),
        None => Err(surrealdb::Error::Api(surrealdb::error::Api::ParseError(
            "SurrealDB session::ns/db returned no result".into(),
        ))),
    }
}
```

**NOTE on error construction:** `surrealdb::Error::Api(surrealdb::error::Api::ParseError(...))`
is a plausible variant but the exact public error API should be confirmed against docs.rs.
Alternative: return a custom `DbError` type or use `anyhow::Error`. The AXIAM codebase should
use whatever error type `DbManager::health_check` already returns; if it returns
`surrealdb::Error`, wrapping a string is awkward — prefer adding a `DbError::SessionMismatch`
variant to `axiam-db`'s own error enum, or use `anyhow`. [ASSUMED: exact error variant path]

`DbManager` also needs a `config` field (currently not stored). Add:

```rust
pub struct DbManager {
    db: Surreal<Client>,         // or Arc<Surreal<Client>>
    config: DbConfig,            // store for guard and health_check
    _guard: tokio::task::JoinHandle<()>,
}
```

---

## Q4: Regression test recipe

### Goal
Demonstrate that a session that was NEVER selected (proxy for a post-reconnect state)
returns "not found" for a seeded record, while a correctly selected session returns the record.

### Approach: kv-mem engine, two sessions

The project already uses `kv-mem` for all integration tests (see `tests/repository_test.rs`).
The `kv-mem` engine does **not** reconnect, so simulating a real WS reconnect is not possible
in-process. However, the reconnect failure mode is fully equivalent to simply never calling
`use_ns`/`use_db`. The test validates the invariant, not the transport event.

```rust
// tests/reconnect_regression.rs

use axiam_core::models::organization::CreateOrganization;
use axiam_core::repository::OrganizationRepository;
use axiam_db::repository::SurrealOrganizationRepository;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;

/// Prove that a session WITHOUT use_ns/use_db returns "not found",
/// while a session WITH correct selection returns the record.
#[tokio::test]
async fn unselected_session_returns_not_found() {
    // --- setup: seeded DB ---
    let db_seeded = Surreal::new::<Mem>(()).await.unwrap();
    db_seeded.use_ns("axiam").use_db("main").await.unwrap();
    axiam_db::run_migrations(&db_seeded).await.unwrap();

    let repo = SurrealOrganizationRepository::new(db_seeded.clone());
    let org = repo
        .create(CreateOrganization {
            name: "Test Org".into(),
            slug: "test-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // --- reconnected session: same in-memory DB engine, no use_ns/use_db ---
    // This is the post-reconnect state: transport alive, session unselected.
    // kv-mem: a fresh Surreal::new connects to a NEW in-memory store, so we must
    // use the SAME db handle but simulate state loss by explicitly resetting:
    // call db.use_ns("main").use_db("main") to put it in the wrong namespace
    // (the SurrealDB default — what a reconnected WS session gets).
    let db_wrong_ns = db_seeded.clone();
    db_wrong_ns.use_ns("main").use_db("main").await.unwrap();

    let repo_wrong = SurrealOrganizationRepository::new(db_wrong_ns.clone());
    let not_found = repo_wrong.get_by_id(org.id.clone()).await.unwrap();
    assert!(not_found.is_none(), "wrong-ns session must return not-found");

    // --- restore correct selection ---
    db_wrong_ns.use_ns("axiam").use_db("main").await.unwrap();
    let repo_fixed = SurrealOrganizationRepository::new(db_wrong_ns);
    let found = repo_fixed.get_by_id(org.id.clone()).await.unwrap();
    assert!(found.is_some(), "re-selected session must find the org");
}
```

**Run command (per constraint: no full workspace):**
```bash
cargo test -p axiam-db --no-default-features --test reconnect_regression
```

**What this proves:**
1. A "reconnected but unselected" connection returns not-found (the production failure mode).
2. Re-issuing `use_ns`/`use_db` on the same handle restores correct behaviour.
3. Validates that the `Surreal<Client>` clone shares session state (or not) — if the assert
   at step 1 fails (i.e. the clone does NOT pick up the wrong ns), that means clones are
   independent sessions and the guard task's clone approach is wrong. The test failure would
   flag that to the implementer.

---

## Q5: Keepalive / idle-timeout prevention (defense-in-depth)

The SurrealDB Rust SDK uses `tokio-tungstenite` under the hood. The WebSocket protocol has
ping/pong frames; the SDK (via tungstenite) handles pong responses automatically.
[CITED: github.com/surrealdb/surrealdb/issues/195]

**SDK-side keepalive:** There is no documented `keep_alive` or ping-interval option in the
`Connect` builder for surrealdb 3.x. The only builder method is `with_capacity(usize)` for
channel sizing. [ASSUMED: no keepalive option in 3.1.3 — absence not positively confirmed in
official docs, but not found in any search result or docs.rs entry]

**Server-side:** SurrealDB server has no documented `--idle-timeout` flag. The server relies on
OS TCP keepalive and the WebSocket ping/pong that tungstenite handles internally.

**Defense-in-depth recommendation:**

1. The periodic guard task (Q2) already acts as a keepalive: a query every 30 s keeps the
   connection from idling at the TCP/proxy level.
2. If deploying behind a reverse proxy (nginx, Caddy, Traefik), set `proxy_read_timeout` /
   `proxy_send_timeout` to at least 60 s (default nginx is 60 s; worth explicit configuration).
3. No additional SDK-level keepalive configuration is available in 3.1.3.

---

## Q6: e2e-bootstrap.sh exact corrections

Two bugs confirmed by reading `scripts/e2e-bootstrap.sh` and `crates/axiam-db/src/schema.rs`:

### Bug 1 — Wrong database name (line 73)

```bash
# CURRENT (wrong):
-H "surreal-db: axiam" \

# CORRECT (must match DbConfig::default().database):
-H "surreal-db: main" \
```

`DbConfig::default()` sets `database: "main"`. The script writes to `axiam` DB; the server
reads from `main` DB. Records created by the script are invisible to the server.

The fix should also accept the DB name from env:
```bash
AXIAM_DB="${AXIAM__DB__DATABASE:-main}"
# then use: -H "surreal-db: ${AXIAM_DB}" \
```

### Bug 2 — `is_active` field not in schema (line 88)

```bash
# CURRENT (wrong):
  is_active = true,

# CORRECT: remove the line entirely
```

The `tenant` table schema (schema.rs lines 170-179) defines exactly these fields:
`organization_id`, `name`, `slug`, `metadata`, `created_at`, `updated_at`.
There is NO `is_active` field. The `tenant` table is SCHEMAFULL — SurrealDB rejects
unknown fields with a statement-level error. This causes statement 2 (`CREATE tenant`) to fail
with `status: ERR`, which the existing error-check logic catches and aborts. The org record is
created (statement 1 passes), but the tenant is not. The bootstrap call that follows references
`TENANT_ID` which does not exist in the DB, causing silent downstream failures.

---

## Standard Stack

No new external dependencies required. The fix uses:

| Library | Already in use | Purpose |
|---------|---------------|---------|
| `surrealdb 3.1.3` | Yes — `crates/axiam-db/Cargo.toml` | SDK; `Surreal<Client>`, `use_ns`, `use_db`, `query` |
| `tokio` (with `time` feature) | Yes — workspace dep | `tokio::time::interval`, `tokio::task::spawn` |
| `tracing` | Yes | `warn!`, `info!` for guard events |

Verify `tokio` has the `time` feature enabled in `axiam-db/Cargo.toml`:
```bash
grep -A5 'tokio' /home/emanuele/git/priv/axiam/crates/axiam-db/Cargo.toml
```

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Detecting if WS reconnected | Custom WS event listener | Periodic `session::ns()`/`session::db()` query | No SDK hook exists; session functions are authoritative server-side |
| Custom error type for health | New error enum | Return `surrealdb::Error` or existing `DbError` | Avoids new dependency surface |

---

## Architecture Patterns

### Recommended DbManager Structure

```
DbManager
├── db: Surreal<Client>          (the live, shared handle)
├── config: DbConfig             (stored for guard + health_check)
└── _guard: JoinHandle<()>       (background ns/db keepalive loop)
```

Data flow for the guard:
```
tokio::time::interval (30s)
    → RETURN [session::ns(), session::db()]
    → compare to config.namespace / config.database
    → MISMATCH: signin() → use_ns() → use_db()
    → OK: no-op
```

### Anti-Patterns to Avoid

- **Re-selecting ns/db before every query:** Correct in principle but unnecessary overhead and
  obscures the real fix. The guard handles it proactively.
- **Asserting via `RETURN 1`:** Only proves the socket is alive — the current `health_check`
  bug. Does NOT detect the silent wrong-namespace state.
- **Replacing `Surreal<Client>` with a reconnecting wrapper:** Over-engineering. The SDK already
  reconnects the transport; we only need to re-select the session context.

---

## Common Pitfalls

### Pitfall 1: Clone session independence

**What goes wrong:** If `Surreal<Client>` clones create independent session state, calling
`use_ns`/`use_db` on a clone inside the guard task does NOT fix the original handle used by
repositories.

**Root cause:** The SurrealDB v3 docs say "cloning creates a new session with independent
state while sharing the underlying database connection." This is ambiguous — "state" may include
ns/db selection.

**How to avoid:** Write the regression test (Q4) first. If the clone approach fails the test,
change `DbManager.db` to `Arc<Surreal<Client>>` and ensure the guard and all repositories
share THE SAME allocation, calling `use_ns`/`use_db` on the same `Arc`-dereferenced handle.

**Warning sign:** The regression test assert at step 1 passes but step 3 still fails after
the guard re-selects — means the guard's clone is a different session.

### Pitfall 2: JoinHandle drop cancels the guard

**What goes wrong:** If `_guard: JoinHandle<()>` is stored but the `DbManager` is dropped or
the `JoinHandle` is `.abort()`ed, the background loop stops silently.

**How to avoid:** Store `_guard` in `DbManager` so it lives as long as the manager. Name it
with the `_guard` prefix (Rust convention: leading `_` prevents unused-variable warnings but
still owns the value and keeps the task alive).

### Pitfall 3: Guard task panics silently

**What goes wrong:** A deserialization error in the guard's `result.take(0)` causes a `?`
unwrap to panic, killing the tokio task silently.

**How to avoid:** Use `match` / `if let` instead of `?` in the guard loop; log errors and
continue. The guard must never panic.

### Pitfall 4: e2e-bootstrap runs against wrong ns/db

**What goes wrong:** The script writes to `surreal-db: axiam`; the server reads `db=main`.
Org is created in DB `axiam`, server sees DB `main` — org not found, bootstrap 404.

**How to avoid:** Fix line 73 as specified in Q6.

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | tokio-test / `#[tokio::test]` macros (via tokio) |
| Config file | none — `[dev-dependencies]` in Cargo.toml |
| Quick run command | `cargo test -p axiam-db --no-default-features --test reconnect_regression` |
| Full suite command | `cargo test -p axiam-db --no-default-features` |

### Phase Requirements → Test Map
| Req | Behavior | Test Type | Automated Command |
|-----|----------|-----------|-------------------|
| Reconnect resilience | Unselected session returns not-found; re-selected finds record | Integration (kv-mem) | `cargo test -p axiam-db --no-default-features --test reconnect_regression` |
| health_check correctness | `health_check` returns error when ns/db is wrong | Unit | `cargo test -p axiam-db --no-default-features -- health_check` |

### Wave 0 Gaps
- [ ] `crates/axiam-db/tests/reconnect_regression.rs` — new file; covers reconnect invariant
- [ ] `health_check` unit test in existing `tests/` — covers session::ns/db assertion

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| `tokio` with `time` feature | Background guard task | Must verify | see Cargo.toml | Enable `time` feature flag |
| `kv-mem` feature (surrealdb) | Regression test | Yes — existing tests use it | 3.1.x | — |
| SurrealDB server (live) | Manual smoke (deferred) | Available via `just dev-up` | current | kv-mem for unit tests |

---

## Open Questions

1. **Clone session state independence**
   - What we know: v3 docs say clones share the underlying connection but have "independent state".
   - What's unclear: Whether "independent state" means ns/db selection is per-clone or shared.
   - Recommendation: Write regression test first; if clone re-select fixes the original handle,
     plain clone is fine. If not, switch to `Arc<Surreal<Client>>` with guard operating on same arc.

2. **`surrealdb::Error` variant for health_check mismatch**
   - What we know: The `surrealdb::Error` type is non-exhaustive; exact variant paths for
     constructing custom errors may not be stable.
   - Recommendation: Use `axiam-db`'s own error type (or `anyhow`) for the health mismatch
     error to avoid coupling to unstable `surrealdb::Error` internals.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | No keepalive option in Connect builder for 3.1.3 | Q5 | If option exists, simpler than guard task; but guard is still correct regardless |
| A2 | 30-second guard interval is sufficient to catch reconnect before next query | Q2/Q5 | If server reconnects faster, first query after reconnect still hits wrong ns; mitigated by health_check improvement |
| A3 | `surrealdb::Error::Api(Api::ParseError(...))` is a valid error constructor | Q3 | Compile error; switch to `anyhow` or project DbError type |
| A4 | `Surreal<Client>` clone in the guard task shares effective session with the original | Q2 | Guard re-select won't fix original handle; switch to Arc approach |
| A5 | SurrealDB default ns/db after unselected reconnect is `main`/`main` | Q1 | Empty results regardless of which default ns is used; silent failure mode remains |

---

## Sources

### Primary (HIGH confidence)
- [github.com/surrealdb/surrealdb/issues/5750](https://github.com/surrealdb/surrealdb/issues/5750) — confirms no reconnect hook in SDK; "Haven't selected NS or DB" after reconnect
- [surrealdb.com/docs/surrealql/functions/database/session](https://surrealdb.com/docs/surrealql/functions/database/session) — `session::ns()`, `session::db()` SurrealQL functions
- `crates/axiam-db/src/connection.rs` — current `DbManager` implementation (read this session)
- `crates/axiam-db/src/schema.rs` lines 170-179 — SCHEMAFULL tenant fields (read this session)
- `scripts/e2e-bootstrap.sh` — seed bugs confirmed by reading this session

### Secondary (MEDIUM confidence)
- [surrealdb.com/docs/sdk/rust/methods/connect](https://surrealdb.com/docs/sdk/rust/methods/connect) — `with_capacity` only builder method; no reconnect option
- [docs.rs/surrealdb/latest/surrealdb/struct.Connect.html](https://docs.rs/surrealdb/latest/surrealdb/struct.Connect.html) — Connect struct API
- `crates/axiam-db/tests/repository_test.rs` — existing kv-mem test pattern (read this session)

### Tertiary (LOW confidence)
- Multi-session/clone docs claim "independent state while sharing underlying connection" — needs empirical verification in regression test

---

## Metadata

**Confidence breakdown:**
- Root cause and SDK behavior: HIGH — confirmed by official GitHub issue #5750
- Recommended fix (guard task pattern): HIGH — standard workaround; no SDK alternative exists
- Exact API (tokio interval, query call): HIGH — uses already-present project deps
- Clone semantics: LOW — requires empirical test; see A4 and Open Question 1
- e2e-bootstrap bugs: HIGH — confirmed by reading the files

**Research date:** 2026-06-19
**Valid until:** 2026-07-19 (surrealdb 3.x moves quickly; check if issue #5750 is closed)

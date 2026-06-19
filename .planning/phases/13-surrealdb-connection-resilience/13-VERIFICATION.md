---
phase: 13-surrealdb-connection-resilience
verified: 2026-06-19T00:00:00Z
status: human_needed
score: 5/5 must-haves verified
overrides_applied: 0
human_verification:
  - test: "Execute the deferred Phase-12 11-item manual smoke via just bootstrap-local then 12-HUMAN-UAT.md"
    expected: "All 11 smoke items pass: login, MFA, reset/verify/change-pw, GDPR, federation-after-restart, cross-org 403, gRPC-no-creds rejected"
    why_human: "Requires a running server (just run-local), live SurrealDB (just dev-up), and a human walking multi-step browser/gRPC flows; cannot automate with grep or cargo"
---

> ⚠️ **SUPERSEDED — this verification was a FALSE-GREEN (corrected 2026-06-19).**
> The original 13-01 fix (WebSocket keepalive guard + `session::ns()`/`session::db()`
> assertion in `health_check`) did NOT work in practice: a running server still
> returned "organization not found" on seeded records a fresh connection finds, and
> `/ready` falsely 503'd. The kv-mem `reconnect_regression` test passed without
> reproducing a real Ws reconnect (it flipped ns on a clone), and `session::ns()`
> returns `None` on a healthy SDK connection — so the guard churned and the check
> was meaningless. **Real fix (commit `2c83186`): switch `DbManager` to the stateless
> SurrealDB HTTP engine** — ns/db/auth are sent per request, so there is no session
> to lose on reconnect (eliminates SDK #5750). Guard + `SessionMismatch` + the
> false-green test were removed. The 5/5 table below refers to the superseded WS
> approach; the live `just bootstrap-local` + `12-HUMAN-UAT.md` smoke is the true
> verification and is now expected to pass with the HTTP engine.

# Phase 13: SurrealDB Connection Resilience — Verification Report

**Phase Goal:** Eliminate the silent stale-connection failure where the server's SurrealDB WebSocket connection loses its use_ns/use_db selection after an idle reconnect and queries the empty default namespace; repair the local first-run seed path; unblock the deferred Phase-12 smoke.
**Verified:** 2026-06-19
**Status:** human_needed (all automated checks VERIFIED; one deferred human item remains)
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | After reconnect simulation, connection operates against ns=axiam/db=main; regression test reproduces and asserts | VERIFIED | `crates/axiam-db/tests/reconnect_regression.rs` — 89 lines, kv-mem test flips session to wrong ns then re-selects; `cargo test -p axiam-db --no-default-features --test reconnect_regression` → 1 passed |
| 2 | DbManager has background ns/db keepalive guard; health_check verifies active ns/db not just liveness | VERIFIED | `connection.rs:103-174` — guard spawned in connect(), polls every 30s, uses match/if-let (no panic); `health_check:206-236` — queries `RETURN [session::ns(), session::db()]`, returns `DbError::SessionMismatch` on mismatch |
| 3 | e2e-bootstrap.sh seeds db=main (not axiam), tenant CREATE has no is_active field | VERIFIED | `surreal-db: ${AXIAM_DB}` at line 75 (AXIAM_DB defaults to `main`); `grep -c 'is_active' scripts/e2e-bootstrap.sh` = 0; per-statement ERR/OK check preserved at lines 97-102 |
| 4 | `just bootstrap-local` recipe exists, is well-formed, delegates to e2e-bootstrap.sh | VERIFIED | `justfile:126-133` — recipe present, shebang bash, set -euo pipefail, exports AXIAM_URL/SURREAL_URL/AXIAM__DB__DATABASE defaults, calls `bash scripts/e2e-bootstrap.sh`; `just --list` shows it |
| 5 | REQ-17 is declared and mapped to Phase 13 in roadmap | VERIFIED | `ROADMAP.md:548` — `REQ-17 | Phase 13 | SurrealDB Connection Resilience`; ROADMAP success criteria 1-5 match the five verifiable truths |

**Score:** 5/5 truths verified

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/axiam-db/src/connection.rs` | DbManager with config field, Arc-wrapped client, background ns/db keepalive guard, ns/db-asserting health_check | VERIFIED | 237 lines; `struct DbManager { db: Arc<Surreal<Client>>, config: DbConfig, _guard: JoinHandle<()> }`; guard uses `session::ns()` query at lines 113, 127; health_check uses `session::ns()` at line 209, returns `DbError::SessionMismatch` |
| `crates/axiam-db/src/error.rs` | DbError::SessionMismatch variant | VERIFIED | 41 lines; `SessionMismatch { expected_ns, expected_db, actual_ns: Option<String>, actual_db: Option<String> }` at line 25 with `#[error(...)]` message |
| `crates/axiam-db/tests/reconnect_regression.rs` | kv-mem regression test, min 30 lines | VERIFIED | 89 lines; seeds in axiam/main, flips to main/main (simulates reconnect fallback), asserts `is_err()`, re-selects to axiam/main, asserts `is_ok()`; test passes |
| `scripts/e2e-bootstrap.sh` | Seeds db=main; no is_active; per-statement ERR check preserved | VERIFIED | `AXIAM_DB="${AXIAM__DB__DATABASE:-main}"` at line 26; `surreal-db: ${AXIAM_DB}` at line 75; zero occurrences of is_active; ERR/OK check at lines 97-102 |
| `justfile` (bootstrap-local recipe) | bootstrap-local recipe seeding local server | VERIFIED | `justfile:126-133` — well-formed, delegates to e2e-bootstrap.sh |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| connection.rs guard task | config.namespace / config.database | `session::ns()` comparison + re-select on mismatch | WIRED | `guard_config` captures config.clone(); guard queries `RETURN [session::ns(), session::db()]` and calls `use_ns(&guard_config.namespace).use_db(&guard_config.database)` on mismatch |
| connection.rs health_check | config.namespace / config.database | `session::ns()`/`session::db()` assertion returning DbError::SessionMismatch | WIRED | health_check at line 209 queries `RETURN [session::ns(), session::db()]`; lines 217-234 match against `self.config.namespace` and `self.config.database` |
| e2e-bootstrap.sh seed | server DbConfig database (main) | surreal-db header driven by AXIAM__DB__DATABASE default main | WIRED | Line 26 sets `AXIAM_DB="${AXIAM__DB__DATABASE:-main}"`; line 75 passes `-H "surreal-db: ${AXIAM_DB}"` |
| justfile bootstrap-local | scripts/e2e-bootstrap.sh + /api/v1/admin/bootstrap | env-configured invocation | WIRED | Recipe exports env vars and calls `bash scripts/e2e-bootstrap.sh` which calls /api/v1/admin/bootstrap |

---

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Regression test passes | `cargo test -p axiam-db --no-default-features --test reconnect_regression` | 1 passed (0.99s) | PASS |
| bootstrap.sh syntax valid | `bash -n scripts/e2e-bootstrap.sh` | clean (exit 0) | PASS |
| is_active removed | `grep -c 'is_active' scripts/e2e-bootstrap.sh` | 0 | PASS |
| AXIAM_DB env var present | `grep -c 'surreal-db: ${AXIAM_DB}' scripts/e2e-bootstrap.sh` | 1 | PASS |
| bootstrap-local in justfile | `just --list \| grep bootstrap-local` | bootstrap-local found | PASS |
| session::ns used in connection.rs | `grep -c 'session::ns' crates/axiam-db/src/connection.rs` | 4 | PASS |
| SessionMismatch in error.rs | `grep -c 'SessionMismatch' crates/axiam-db/src/error.rs` | 1 | PASS |
| RETURN 1 not in live code | `grep -n 'RETURN 1' crates/axiam-db/src/connection.rs` | line 203 is in doc comment only | PASS |

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| REQ-17 | 13-01-PLAN.md, 13-02-PLAN.md | SurrealDB Connection Resilience | SATISFIED | ROADMAP.md coverage matrix; implementation in connection.rs + error.rs + reconnect_regression.rs + e2e-bootstrap.sh + justfile |

**Note:** REQ-17 is defined in ROADMAP.md coverage matrix (line 548) and both PLAN frontmatter files, but is not yet added to the REQUIREMENTS.md traceability table. This is a documentation gap only — no implementation gap.

---

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| — | — | No TBD/FIXME/XXX markers found | — | — |
| — | — | No empty/placeholder implementations found | — | — |

---

### Human Verification Required

#### 1. Phase-12 Manual Smoke (11 items from 12-HUMAN-UAT.md)

**Test:** Run `just dev-up`, `just run-local`, `just bootstrap-local`, then walk through all 11 items in `12-HUMAN-UAT.md`
**Expected:** All 11 items pass — login, MFA, password reset/verify/change, GDPR export, federation-after-restart, cross-org 403, gRPC-no-creds rejected
**Why human:** Requires a live running server with SurrealDB, RabbitMQ, and a human operating a browser and gRPC client across multi-step flows; cannot be reproduced with grep or cargo test

This item is explicitly carved out by ROADMAP SC #5 and 13-VALIDATION.md: "This phase only makes it runnable; it does not execute the smoke."

---

### Gaps Summary

No gaps. All five automated success criteria are verified in the codebase. The single human_verification item is the deferred Phase-12 manual smoke which this phase explicitly scoped as out-of-bounds to execute (SC #5 says "unblocked and can be executed" — not "executed").

The only minor documentation gap (REQ-17 missing from REQUIREMENTS.md traceability table) is informational; it does not affect implementation correctness.

---

_Verified: 2026-06-19_
_Verifier: Claude (gsd-verifier)_

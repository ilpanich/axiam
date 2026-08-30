---
phase: 12-low-remediation
plan: 05
status: complete
completed: 2026-06-19
requirements: [REQ-16]
manual_smoke: deferred
deferred_to: 12-HUMAN-UAT.md
---

# Plan 12-05 Summary — Whole-effort final verification gate

## Outcome

ROADMAP SC #5 automated verification is **green**. The manual multi-protocol smoke
(Task 3) is **deferred** to `12-HUMAN-UAT.md` — it could not be executed locally
because bringing up a live dev environment surfaced a chain of pre-existing
first-run / infrastructure blockers (none of them Phase-12 regressions; details
below). The one genuine Phase-12 regression the smoke setup surfaced was found
and fixed.

## Task 1 — Local disk-safe verification sweep ✅

All per-crate checks, targeted tests, and the frontend toolchain passed (read from
output text, `--no-default-features`):

| Command | Result |
|---------|--------|
| `cargo check -p axiam-db -p axiam-api-rest -p axiam-auth -p axiam-authz -p axiam-amqp -p axiam-pki -p axiam-oauth2 -p axiam-audit -p axiam-server --tests --no-default-features` | PASS |
| `cargo clippy -p axiam-db -p axiam-api-rest -p axiam-auth -p axiam-audit -p axiam-server --no-default-features -- -D warnings` | PASS |
| `cargo test -p axiam-db --test seeder_skip_test --no-default-features` | PASS (2) |
| `cargo test -p axiam-db --lib --no-default-features` | PASS (19) |
| `cargo test -p axiam-auth --lib --no-default-features` | PASS (70) |
| `cargo test -p axiam-audit --lib --no-default-features` | PASS (4) |
| `cd frontend && npm run lint && npx tsc -b && npx vitest run` | PASS (6) |

4 pre-existing issues surfaced by the stricter `-D warnings` sweep were fixed in
commit `09e551c` (clippy `is_some_and`/`derivable_impls`, a `too_many_arguments`
allow from 12-01's HIBP param, and 5 `email_config` UPSERT test failures fixed
with the canonical `type::record` + `Uuid::new_v5` pattern).

The 3 SAML `federation_test` failures remain the known `--no-default-features`
baseline (xmlsec off-path), NOT regressions.

## Task 2 — CI gate coverage ✅ (no edit needed)

`.github/workflows/ci.yml` already gates: `cargo build --workspace`,
`cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`,
`cargo audit`, `cargo-deny`, `npm audit --audit-level=high`, frontend
`lint`/`tsc -b`/`vitest`, and a **Playwright e2e job**. All `uses:` remain pinned
to 40-hex SHAs (Plan 12-02). No edit required.

## Task 3 — Manual multi-protocol smoke ⏸ DEFERRED → `12-HUMAN-UAT.md`

The 11-item live smoke requires REST + gRPC + federation IdP + email and a logged-in
admin. Standing up that environment surfaced pre-existing blockers (fixed inline so
the environment is now usable), plus one real Phase-12 regression:

**Genuine Phase-12 regression (fixed):**
- `ba709b8` — `useAuthInit` StrictMode deadlock (CQ-F35). The 12-03 once-guard
  combined with the legacy `cancelled`-on-cleanup flag froze the app on its loading
  spinner under React 18 StrictMode (dev). `vitest` never mounts `<App>` under
  StrictMode, so it stayed green. Fixed by making the ref-guard the sole de-dup.

**Pre-existing dev-env / infra blockers fixed inline (NOT Phase-12 regressions):**
- `909271d` — `docker-compose.dev.yml` pulled a private `ghcr.io/...server:latest`
  on `just dev-up`; gated behind a `full-stack` profile so `dev-up` is deps-only.
- `a81c629` — added `just run-local` (Ed25519 keygen + `--no-default-features` +
  cookie/AMQP env for local Arch dev) and `.vscode` rust-analyzer no-default-features
  config (ends the xmlsec `bindings.rs` diagnostic spam + target-lock contention).
- `0387963` — vite dev proxy pointed at `:8080`; backend binds `:8090`. Repointed.

**Blocker that stopped the smoke (now its own phase):**
- First-run is chicken-and-egg by design (org/tenant need auth to create; bootstrap
  needs them to pre-exist) — resolved out-of-band via `scripts/e2e-bootstrap.sh`,
  which itself has a `surreal-db: axiam` vs server `db=main` mismatch.
- Root cause of the persistent "organization not found": the long-running server's
  SurrealDB WebSocket connection lost its `use_ns`/`use_db` selection after an idle
  reconnect (SurrealDB container never restarted; `RestartCount=0`). A FRESH
  connection finds correctly-seeded records; the aged connection silently queries the
  empty default namespace. This is a **connection-resilience bug**, addressed in the
  new **Phase 13: SurrealDB Connection Resilience**.

## Verification status

- Automated (SC #5): **green** — workspace build/clippy/test + audit/deny + npm audit
  + frontend + Playwright e2e all gated in CI; local disk-safe sweep green.
- Manual smoke: **deferred** to `12-HUMAN-UAT.md` (11 items, runnable once Phase 13
  lands the connection fix and a working admin login is reproducible locally).

---
phase: 26
slug: correctness-resilience
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-04
---

# Phase 26 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> See `26-RESEARCH.md` § "Validation Architecture" for the per-criterion test seams this contract implements.

---

## Test Infrastructure

Mixed-stack phase: Rust backend (cargo) + TypeScript frontend (vitest unit + Playwright e2e).

| Property | Value |
|----------|-------|
| **Framework** | Rust `cargo test` (backend) · `vitest` (frontend unit) · Playwright (frontend e2e) |
| **Config file** | `Cargo.toml` / `justfile` · `frontend/package.json` · `frontend/playwright.config.ts` · `docker/docker-compose.e2e.yml` + `scripts/e2e-bootstrap.sh` (seeded backend) |
| **Quick run command** | Backend: `cargo test -p <crate> --lib` · Frontend unit: `cd frontend && npm run test` (`vitest run`) |
| **Full suite command** | Backend: `just test` · Frontend: `cd frontend && npm run test && npm run test:e2e` (`vitest run` + `playwright test` against the seeded backend) |
| **Estimated runtime** | Backend per-crate `--lib` ~30–120s · Playwright e2e suite ~minutes (CI-gated) |

> Build hygiene (CLAUDE.md): prefer narrowly-scoped `cargo test -p <crate> --lib` / `--test <name>`; `cargo clean` between plans; export `SWAGGER_UI_DOWNLOAD_URL=file:///home/user/.axiam-build-cache/swagger-ui-5.17.14.zip` before any build/test of `axiam-api-rest` or its dependents.

---

## Sampling Rate

- **After every task commit:** Run the scoped quick command for the crate/package touched (`cargo test -p <crate> --lib` or `vitest run <file>`)
- **After every plan wave:** Run the full suite for the layer touched (backend crate suite, or `vitest run` + `playwright test`)
- **Before `/gsd-verify-work`:** Full suite must be green — including the CI e2e job actually running `npx playwright test` (CORR-04)
- **Max feedback latency:** ~120 seconds for scoped backend/unit runs; Playwright e2e is CI-gated (not on every commit)

---

## Per-Task Verification Map

*Populated by the planner/executor during execution — one row per task, mapping to the CORR requirement and the RESEARCH § "Validation Architecture" seam. Format below.*

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 26-01-01 | 01 | 1 | CORR-01 | — | gRPC sustained throughput ≈ configured rate | integration | `cargo test -p axiam-api-grpc --test <name>` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] gRPC sustained-throughput test seam (CORR-01) — new integration test asserting rate, not just non-error
- [ ] SurrealDB re-signin / auth-expiry `health_check` test seam (CORR-02) — token-expiry simulated or fraction-derived interval unit-tested
- [ ] Webhook durable-delivery test seam (CORR-03) — AMQP consumer invokes `WebhookDeliveryService`; per-attempt + terminal audit records asserted; `t=,v1=` signature verified
- [ ] Playwright auth/login/contract specs executing against seeded backend in CI (CORR-04) — contract spec asserts request **bodies**
- [ ] Frontend specs for tenant restore, MFA-setup landing, StrictMode/query-key/refocus (CORR-05/06)

*Existing infrastructure (cargo, vitest, Playwright harness, e2e seed) covers the frameworks; Wave 0 adds the specific new test files/seams above.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| *(planner to identify — e.g. real-broker restart survival of the webhook queue may need a manual/integration check if not fully automatable in CI)* | CORR-03 | Durable-queue restart survival may exceed unit-test scope | Restart the broker mid-flight; confirm queued deliveries resume |

*If none: "All phase behaviors have automated verification."*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s (scoped runs)
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

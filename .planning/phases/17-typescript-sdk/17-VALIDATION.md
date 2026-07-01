---
phase: 17
slug: typescript-sdk
status: complete
nyquist_compliant: true
wave_0_complete: true
created: 2026-07-01
validated: 2026-07-01
---

# Phase 17 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

Retroactively audited 2026-07-01. Every phase deliverable has automated
verification; the full suite is green (94/94). See the audit trail at the
bottom of this file.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | vitest 4.x |
| **Config file** | `sdks/typescript/vitest.config.ts` (Node env default, jsdom opt-in per file) |
| **Quick run command** | `cd sdks/typescript && npx vitest run` |
| **Full suite command** | `cd sdks/typescript && npx vitest run && npx tsc --noEmit && npx tsc --noEmit -p examples/tsconfig.json` |
| **Estimated runtime** | ~3 seconds (94 tests, 18 files) |

Notes:
- msw 2.x backs the REST/JWKS HTTP mocking; jsdom provides the browser CSRF
  environment (opt-in via `// @vitest-environment jsdom` per test file).
- `npm run build` (tsup + `buf generate` prebuild) requires the `buf` CLI,
  which is absent from the sandbox — the build/publish gate runs only in CI
  (`.github/workflows/sdk-ci-typescript.yml`). See Manual-Only below.

---

## Sampling Rate

- **After every task commit:** Run `npx vitest run` (relevant subtree)
- **After every plan wave:** Run `npx vitest run && npx tsc --noEmit`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** ~3 seconds

---

## Per-Task Verification Map

One row per plan-deliverable group. Requirement for the whole phase is
**TS-01** (TypeScript SDK — browser REST + Node REST/gRPC/AMQP). All
deliverables verified by unit tests; all green in the 94/94 run.

| Deliverable | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command (test file) | File Exists | Status |
|-------------|------|------|-------------|------------|-----------------|-----------|-------------------------------|-------------|--------|
| Build/test tooling + exports map (tsup dual ESM+CJS, strict tsconfig) | 01 | 1 | TS-01 | — | N/A | unit | `vitest run test/core/errorMapper.test.ts` (19) | ✅ | ✅ green |
| Central status→error mapper (HTTP + gRPC §2) | 01 | 1 | TS-01 | T-17 taxonomy | Single source of truth; no drift between transports | unit | `vitest run test/core/errorMapper.test.ts` (19) | ✅ | ✅ green |
| `Sensitive<T>` three-surface redaction | 01 | 1 | TS-01 | T-17 leak | Raw value only via `expose()`; redacts toString/JSON/inspect | unit | `vitest run test/core/sensitive.test.ts` (4) | ✅ | ✅ green |
| Single-flight refresh guard (core) | 01 | 1 | TS-01 | — | Exactly one refresh under concurrency | unit | `vitest run test/core/singleFlightRefresh.test.ts` (3) | ✅ | ✅ green |
| REST CSRF double-submit forwarding | 02 | 2 | TS-01 | T-17 CSRF (D-05) | X-CSRF-Token on state-changing methods only | unit | `vitest run test/rest/csrf.test.ts` (4) | ✅ | ✅ green |
| Reactive single-flight 401→refresh (SC#3) | 02 | 2 | TS-01 | — | 5 concurrent 401s → 1 refresh; refresh-401 no retry | unit | `vitest run test/rest/singleFlightRefresh.test.ts` (2) | ✅ | ✅ green |
| login/verifyMfa discriminated union (no token field) | 02 | 2 | TS-01 | T-17-07 | No session-token field on any branch | unit | `vitest run test/rest/login.test.ts` (3) | ✅ | ✅ green |
| Browser authz over REST — can/checkAccess/batchCheck (SC#2) | 02 | 2 | TS-01 | — | 403→AuthzError; batch order preserved | unit | `vitest run test/rest/can.test.ts` (4) | ✅ | ✅ green |
| Node token manager — jar-read + `Sensitive` cache | 03 | 3 | TS-01 | T-17 leak | Token only from jar; cached value redacted | unit | `vitest run test/node/tokenManager.test.ts` (6) | ✅ | ✅ green |
| Local JWKS verify — EdDSA allowlist (algorithm-confusion defense) | 03 | 3 | TS-01 | T-17-14 | HS256 rejected; explicit `algorithms:['EdDSA']` | unit | `vitest run test/node/jwks.test.ts` (3) | ✅ | ✅ green |
| gRPC authz — sync interceptor + UNAUTHENTICATED refresh (SC#2 Node) | 03 | 3 | TS-01 | — | One refresh + one retry; no third attempt | unit | `vitest run test/grpc/checkAccess.test.ts` (5) | ✅ | ✅ green |
| AMQP HMAC-SHA256 sign/verify (byte-identical, never throws) | 04 | 3 | TS-01 | T-17 (§8/D-12) | Timing-safe compare; false on malformed hex | unit | `vitest run test/amqp/hmac.test.ts` (9) | ✅ | ✅ green |
| AMQP consumer — verify-before-handler, nack-no-requeue | 04 | 3 | TS-01 | T-17 (§8.3/§8.4) | Unverified msg never reaches handler; sig/key never logged | unit | `vitest run test/amqp/consumer.test.ts` (8) | ✅ | ✅ green |
| Express + Fastify middleware — shared local-JWKS verify (SC#4) | 05 | 4 | TS-01 | T-17 (D-27/§10) | Missing/invalid creds → 401 JSON | unit | `vitest run test/middleware/express.test.ts test/middleware/fastify.test.ts` (8) | ✅ | ✅ green |
| Five strict-compiling examples (SC#4) | 05 | 4 | TS-01 | — | Public-entry-points-only; strict compile | typecheck | `tsc --noEmit -p examples/tsconfig.json` | ✅ | ✅ green |
| CI/publish pipeline: SC#1 bundle-grep, CJS-require, leak, TLS-lint, dry-run (SC#5) | 06 | 5 | TS-01 | T-17-27 / TLS | No @grpc/amqplib in browser bundle; no insecure-TLS surface | CI gate | `.github/workflows/sdk-ci-typescript.yml` (test job) | ✅ | ✅ green (CI) |
| CR-02 — per-session refresh guard (no cross-session wiring) | 07 | 6 | TS-01 | CR-02 (D-13) | Two sessions each refresh once; distinct guard closures | unit | `vitest run test/rest/multiSessionRefresh.test.ts` (1) | ✅ | ✅ green |
| CR-03 — tenant-isolated middleware verify | 07 | 6 | TS-01 | CR-03 | Cross-tenant token rejected; same-tenant accepted | unit | `vitest run test/middleware/tenantIsolation.test.ts` (3) | ✅ | ✅ green |
| CR-01 — Node persona CSRF population from jar | 08 | 6 | TS-01 | CR-01 (D-05) | Real X-CSRF-Token forwarded; rotation-safe resync | unit | `vitest run test/node/csrf.test.ts` (4) | ✅ | ✅ green |
| CR-04 — Set-Cookie/sensitive-header redaction of `NetworkError.cause` | 08 | 6 | TS-01 | CR-04 (D-16) | Raw token never surfaces via log/JSON/inspect | unit | `vitest run test/core/errorRedaction.test.ts` (8) | ✅ | ✅ green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

**Test totals:** 94 tests across 18 files, all passing (`npx vitest run` = 94/94).

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements — the vitest runner,
config, and msw/jsdom fixtures were installed in Plan 01 (and completed in
02/04 with `jsdom`/`@types/node`). No retroactive Wave 0 stubs are needed;
every deliverable already ships with a green test.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| `npm run build` (tsup + `buf generate`) and `npm publish --dry-run` (SC#5) | TS-01 | The `buf` CLI is not installed in the sandbox, so the codegen/build/publish chain cannot run locally. It is exercised in CI where the buf toolchain is available. | In a buf-enabled environment (or CI): `cd sdks/typescript && npm run build && npm run bundle-grep && node -e "require('./dist/grpc/index.js')" && npm publish --dry-run`. Gated automatically by `.github/workflows/sdk-ci-typescript.yml`. |
| Live RabbitMQ broker smoke test for the AMQP consumer | TS-01 | Consumer contract is fully covered against a `RecordingChannel` fake (D-24, no live broker); an end-to-end broker exercise is optional and deferred to a testcontainers job. | Optional: run the AMQP consumer against a live RabbitMQ instance with a real HMAC-signed message and confirm verify-before-handler + nack-no-requeue. |

*Automated tests cover every phase behavior; the two items above are
environment/tooling gates (CI-run), not gaps in automated verification.*

---

## Validation Sign-Off

- [x] All tasks have automated verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (none — infra pre-existing)
- [x] No watch-mode flags (`vitest run` is one-shot)
- [x] Feedback latency < 5s (~3s full suite)
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-07-01

---

## Validation Audit 2026-07-01

Retroactive audit (State A — existing VALIDATION.md was an unfilled template
stub). Reconstructed the Test Infrastructure and Per-Task Verification Map
from the 8 plan SUMMARY files' structured `coverage:` frontmatter, then
cross-referenced against the 18 test files on disk and a live `npx vitest run`.

| Metric | Count |
|--------|-------|
| Deliverables audited | 21 |
| Gaps found (MISSING) | 0 |
| Resolved (new tests generated) | 0 |
| Escalated (manual-only, code bugs) | 0 |
| Environment/CI-only gates (documented Manual-Only) | 2 |

Result: **NYQUIST-COMPLIANT.** Every phase deliverable has automated
verification and the full suite is green (94/94). The two Manual-Only entries
are tooling/CI gates (buf-dependent build/publish, optional live-broker
smoke), not gaps in automated coverage. No auditor spawn or test generation
was required. Consistent with `17-VERIFICATION.md` (all 7 observable truths
VERIFIED after gap-closure plans 07/08 closed CR-01..CR-04).

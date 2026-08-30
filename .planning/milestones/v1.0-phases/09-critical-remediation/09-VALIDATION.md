---
phase: 9
slug: critical-remediation
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-11
---

# Phase 9 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Derived from `09-RESEARCH.md` § Validation Architecture.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework (Rust)** | `cargo test` (built-in) + actix-web test server + in-process SurrealDB Mem |
| **Framework (gRPC)** | Tonic in-process TcpListener + client stubs |
| **Framework (frontend)** | Playwright 1.58 (`npm test --prefix frontend`) |
| **Config file** | Cargo workspace; `frontend/playwright.config.ts` |
| **Quick run command** | `cargo check -p <changed_crate> --tests 2>&1 \| tail -5` |
| **Full suite command** | `cargo test -p axiam-api-rest -p axiam-api-grpc -p axiam-federation 2>&1` + `npm test --prefix frontend` |
| **Estimated runtime** | ~90 seconds (Rust) + ~60 seconds (Playwright) |

---

## Sampling Rate

- **After every task commit:** Run `cargo check -p <changed_crate> --tests 2>&1 | tail -5`
- **After every plan wave:** Run full Rust suite + `npm test --prefix frontend`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 90 seconds (Rust quick-check)

> Per CLAUDE.md: verify via cargo OUTPUT text, never exit code / IDE diagnostics (rtk masks exit codes). Build only changed crates with `-p`, never the full workspace.

---

## Per-Task Verification Map

| Req (AC) | Wave | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|----------|------|-----------------|-----------|-------------------|-------------|--------|
| REQ-13-AC1 | 0→1 | Cross-org `GET /orgs/{other}` returns 403 | integration | `cargo test -p axiam-api-rest --test organization_test` | ❌ W0 (add cross-org case) | ⬜ pending |
| REQ-13-AC1 | 0→1 | Cross-org `GET /orgs/{id}/tenants` returns 403 | integration | `cargo test -p axiam-api-rest --test tenant_test` | ❌ W0 (add cross-org case) | ⬜ pending |
| REQ-13-AC1 | 0→1 | Cross-org `GET /orgs/{id}/ca-certificates` returns 403 | integration | `cargo test -p axiam-api-rest --test ca_certificate_test` | ❌ W0 (add cross-org case) | ⬜ pending |
| REQ-13-AC1 | 1 | org `create`/`list` restricted to system-admin (seeder) | integration | `cargo test -p axiam-api-rest --test organization_test` | ❌ W0 | ⬜ pending |
| REQ-13-AC2 | 0→1 | gRPC call w/o bearer → `UNAUTHENTICATED` | integration | `cargo test -p axiam-api-grpc --features client --test grpc_auth_test` | ❌ W0 (new file) | ⬜ pending |
| REQ-13-AC2 | 0→1 | gRPC call w/ valid bearer → succeeds, claims derived | integration | `cargo test -p axiam-api-grpc --features client --test grpc_auth_test` | ❌ W0 (new file) | ⬜ pending |
| REQ-13-AC3 | 0→1 | reset page calls `/api/v1/auth/reset` | E2E/contract | `npm test --prefix frontend -- --grep "auth contract"` | ❌ W0 (new spec) | ⬜ pending |
| REQ-13-AC3 | 0→1 | MFA enroll calls `/api/v1/auth/mfa/setup/enroll` | E2E/contract | `npm test --prefix frontend -- --grep "auth contract"` | ❌ W0 | ⬜ pending |
| REQ-13-AC4 | 0→1 | Silent refresh POST includes `X-CSRF-Token` (via `api` instance) | unit/contract | `npm test --prefix frontend -- --grep "csrf"` | ❌ W0 | ⬜ pending |
| REQ-13-AC4 | 1 | Boot init attempts refresh once before declaring unauth | manual smoke | Manual: expire access cookie, reload app | manual-only | ⬜ pending |
| REQ-13-AC5 | 0→1 | OIDC login succeeds after restart with encrypted secret | integration | `cargo test -p axiam-api-rest --test federation_test` | ❌ W0 (encrypt/decrypt round-trip) | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `crates/axiam-api-rest/tests/organization_test.rs` — add cross-org 403 cases (org / tenant / ca-cert) + system-admin restriction case
- [ ] `crates/axiam-api-grpc/tests/grpc_auth_test.rs` — **new file**: interceptor accept/reject tests (`--features client`)
- [ ] `frontend/e2e/auth-contract.spec.ts` — **new Playwright spec**: contract test asserting all 6 auth endpoint URLs + CSRF header on refresh
- [ ] `crates/axiam-api-rest/tests/federation_test.rs` — add encrypt-on-create / decrypt-at-use round-trip + post-restart login case

> NOTE (from research § Project Constraints): 3 pre-existing SAML `federation_test` failures under `--no-default-features` are a known baseline, NOT a regression. A 4th+ failure is real.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Boot refresh before unauth declaration | REQ-13-AC4 | Requires real browser cookie-expiry timing; Playwright can assert the network call but the "once before clearAuth" ordering is a smoke check | Expire/delete the access cookie (keep refresh cookie), reload the app, confirm one refresh POST fires and session restores rather than redirect-to-login |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references (4 test files above)
- [ ] No watch-mode flags
- [ ] Feedback latency < 90s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

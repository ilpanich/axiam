---
phase: 7
slug: compliance-verification-test-closure
status: draft
nyquist_compliant: true
wave_0_complete: false
created: 2026-06-07
---

# Phase 7 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Derived from `07-RESEARCH.md` § Validation Architecture. Per-task map is finalized by the planner.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework (Rust)** | `actix-rt` + `#[actix_web::test]` integration tests; in-memory SurrealDB (`Mem`) + hardcoded Ed25519 test keypairs |
| **Framework (gRPC)** | `tonic` in-process server (net-new harness, D-10) — ephemeral localhost port + real client channel |
| **Framework (Frontend)** | `@playwright/test` 1.58.2 |
| **Config file** | none for Rust (cargo); `frontend/playwright.config.ts` |
| **Quick run command** | `cargo test -p <affected-crate>` (per-crate, NEVER `--workspace` locally) |
| **Full suite command** | `just test` (DEFAULT features, SAML ON) + `cd frontend && npm test` |
| **Estimated runtime** | Rust per-crate ~10–60s; full `just test` minutes; E2E suite minutes (separate CI job) |

---

## Sampling Rate

- **After every task commit:** `cargo test -p <affected-crate>` (per-crate scope).
- **After every plan wave:** `just test` (full suite, default features).
- **Before `/gsd:verify-work`:** `just test` green AND `cd frontend && npm test` green AND `docs/compliance/` artifacts complete.
- **Max feedback latency:** < 120 seconds for per-crate sampling.

> **Baseline exclusion (D-06 / SAGE):** the 3 `--no-default-features` SAML failures (`saml_acs`, `saml_authn`, `saml_metadata`) are the accepted baseline, NOT regressions. The green bar is `just test` (SAML ON). A 4th+ failure on the default suite is a real regression. Do NOT expand `build-no-saml` to `--tests` in this phase.

---

## Per-Task Verification Map

> Task IDs are assigned during planning. The planner MUST attach an `<automated>` verify command (or a Wave-0 dependency) to every task, mapped to the requirement/behavior below. Representative rows:

| Behavior | Requirement | Test Type | Automated Command | Target File | Status |
|----------|-------------|-----------|-------------------|-------------|--------|
| gRPC authz check_access: allow + deny | REQ-11 (T19.1) | integration | `cargo test -p axiam-api-grpc grpc_authz` | `crates/axiam-api-grpc/tests/grpc_authz_test.rs` | ⬜ pending (Wave 0) |
| gRPC batch + concurrent authz | REQ-11 (T19.2) | integration | `cargo test -p axiam-api-grpc grpc_batch` | `crates/axiam-api-grpc/tests/` | ⬜ pending (Wave 0) |
| PKI: CA gen + cert sign + mTLS reject (expired/wrong-CA) | REQ-11 (AC-4, D-09) | integration | `cargo test -p axiam-pki` | `crates/axiam-pki/tests/{ca,cert,mtls,pgp}_test.rs` | ⬜ pending (Wave 0) |
| OAuth2 RFC 6749/7636 MUST matrix | REQ-11 (D-07) | integration | `cargo test -p axiam-api-rest oauth2_conformance` | `crates/axiam-api-rest/tests/oauth2_conformance.rs` | ⬜ pending (Wave 0) |
| OIDC Core 1.0 MUST matrix | REQ-11 (D-07) | integration | `cargo test -p axiam-api-rest oidc_conformance` | `crates/axiam-api-rest/tests/oidc_conformance.rs` | ⬜ pending (Wave 0) |
| Frontend E2E: login + RBAC-gated nav + federation | REQ-11 (AC-5, D-11) | e2e | `cd frontend && npm test` | `frontend/e2e/*.spec.ts` (all 11 rewritten) | ⬜ pending (Wave 0) |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

New test files / infra that must exist before downstream tasks can be validated:

- [ ] `crates/axiam-api-grpc/tests/grpc_authz_test.rs` — gRPC authz (T19.1) + batch/concurrent (T19.2)
- [ ] gRPC client-stub generation (feature flag in `build.rs` OR test crate) — currently `build_client(false)` (no client stubs)
- [ ] `crates/axiam-pki/tests/ca_test.rs` — CA keypair gen + signing (D-09)
- [ ] `crates/axiam-pki/tests/cert_test.rs` — leaf cert issuance/validation chain (D-09)
- [ ] `crates/axiam-pki/tests/mtls_test.rs` — mTLS verify incl. reject cases (D-09)
- [ ] `crates/axiam-pki/tests/pgp_test.rs` — PGP audit-sign sign+verify roundtrip (D-09)
- [ ] `crates/axiam-api-rest/tests/oauth2_conformance.rs` — RFC 6749/7636 MUST gaps (~6 behaviors on top of existing 37-test `oauth2_flow_test.rs`)
- [ ] `crates/axiam-api-rest/tests/oidc_conformance.rs` — OIDC Core MUST gaps (discovery completeness, JWKS, userinfo, alg pinning)
- [ ] `docs/compliance/asvs-l2-checklist.md` — D-12 per-control rows (V2,V3,V4,V6,V7,V8,V9,V10,V14)
- [ ] `docs/compliance/oauth2-rfc-compliance.md` — D-01 MUST matrix
- [ ] `docs/compliance/oidc-conformance.md` — D-01 MUST matrix
- [ ] `docs/compliance/FINDINGS.md` — D-05 deferred findings register
- [ ] `frontend/e2e/helpers/auth.ts` — shared real-login helper (replaces inert `sessionStorage.setItem("axiam-auth")`)
- [ ] E2E CI service (docker-compose + seeded DB) — D-13/D-14
- [ ] `.github/workflows/ci.yml` — E2E job addition (D-14), conformance tests in existing test job, preserve `build-no-saml` guard (D-06)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| ASVS L2 checklist completeness (no open items) | REQ-11 (AC-1, D-12) | Human/auditor judgment that each in-scope control is Pass / N-A / Deferred-with-rationale | Review `docs/compliance/asvs-l2-checklist.md` — every in-scope control (V2,V3,V4,V6,V7,V8,V9,V10,V14) has a status + `file:line`/test-name evidence |
| Deferred-findings register accuracy | REQ-11 (D-05) | Cross-check each deferred finding has a matching GitHub `compliance` issue | Review `docs/compliance/FINDINGS.md` rows ↔ open GitHub issues |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify (Plan 04 reordered: live stack first, spec rewrites verified by a real Playwright run, not only tsc/grep)
- [x] Wave 0 covers all MISSING references (new test files + gRPC client-stub infra + E2E CI service)
- [x] No watch-mode flags
- [x] Feedback latency < 120s (per-crate cargo test; E2E job is the separate behavioral gate)
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** nyquist-compliant (revision: Plan 04 Nyquist gap closed — live-stack-first + behavioral Playwright verify)

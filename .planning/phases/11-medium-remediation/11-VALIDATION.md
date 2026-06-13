---
phase: 11
slug: medium-remediation
status: planned
nyquist_compliant: true
wave_0_complete: false
created: 2026-06-13
---

# Phase 11 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust: built-in `#[tokio::test]` + actix-web test helpers (per-crate integration tests under `crates/*/tests/`); Frontend: vitest + Playwright (`frontend/`) |
| **Config file** | `vitest.config.ts` (frontend); Rust uses `Cargo.toml` per-crate |
| **Quick run command** | `cargo check -p <affected-crate>` (per-task) |
| **Full suite command** | `cargo check -p axiam-db -p axiam-api-rest -p axiam-auth -p axiam-api-grpc -p axiam-amqp -p axiam-pki -p axiam-oauth2` + `cd frontend && npx tsc -b --noEmit && npm run lint` |
| **Estimated runtime** | ~60–180s (targeted; full workspace build forbidden) |

> **DISK CONSTRAINT (MEMORY.md):** `/home` is near-full. Do NOT run `cargo build --workspace`, `cargo test --workspace`, or `just test`. Whole-workspace linking hits `os error 28`. Use `-p <crate>` targeted `cargo check` + targeted `--test` only. Reclaim space via `rm -rf target/debug/incremental` if needed.

---

## Sampling Rate

- **After every task commit:** Run `cargo check -p <affected-crate>` (Rust) or `cd frontend && npx tsc -b --noEmit` (frontend).
- **After every plan wave:** Run targeted `cargo test -p <crate> --test <test>` for the behaviors changed in that plan, plus `cargo check` on all affected crates.
- **Before `/gsd:verify-work`:** Full targeted suite green — all affected crates `cargo check` clean; frontend `tsc -b --noEmit && npm run lint` clean.
- **Max feedback latency:** ~180 seconds (targeted checks only).

---

## Per-Task Verification Map

> Task IDs are assigned at plan granularity until plans are finalized (planner produces `11-01`…`11-05`). Each row is the **secure behavior contract** the planner must attach as `<acceptance_criteria>` and the verifier must confirm.

| Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 11-01 | 1 | REQ-15 (AC-1) | — | Duplicate/index violation maps to HTTP 409 (`DbError::AlreadyExists`) | unit/integration | `cargo test -p axiam-db --lib -- helpers` | ❌ W0 (helpers.rs) | ⬜ pending |
| 11-01 | 1 | REQ-15 (AC-1) | — | Shared repo helpers + request DTOs compile in place of per-repo structs | compilation | `cargo check -p axiam-db -p axiam-api-rest` | ✅ | ⬜ pending |
| 11-02 | 2 | REQ-15 (AC-1) | T-11 gRPC limits | gRPC builder sets `max_decoding_message_size` + `timeout` + concurrency/TLS limits | source assertion | read `axiam-api-grpc/src/server.rs` | ✅ | ⬜ pending |
| 11-02 | 2 | REQ-15 (AC-2) | SSRF | Webhook to `127.0.0.1`/private IP rejected; IP re-resolved & pinned at delivery | unit | `cargo test -p axiam-api-rest --lib -- webhook_ssrf` | ❌ W0 | ⬜ pending |
| 11-02 | 2 | REQ-15 (AC-2) | mTLS chain | Forged leaf cert rejected; valid chain to tenant/org CA accepted | unit | `cargo test -p axiam-pki --test mtls_chain_test` | ❌ W0 | ⬜ pending |
| 11-02 | 2 | REQ-15 (AC-2) | PKCE downgrade | Public client auth-code request without S256 PKCE → `InvalidRequest` (400) | unit | `cargo test -p axiam-oauth2 --lib -- authorize` | ✅ | ⬜ pending |
| 11-02 | 2 | REQ-15 (AC-2) | rate limit | `/auth/mfa/*` + `/oauth2/introspect|revoke` throttled (429 past limit) | source assertion | read `axiam-api-rest/src/server.rs` | ✅ | ⬜ pending |
| 11-02 | 2 | REQ-15 (AC-2) | AMQP auth | AMQP authz/mail messages authenticated & tenant-scoped | source assertion | read `axiam-amqp` consumer | ✅ | ⬜ pending |
| 11-03 | 3 | REQ-15 (AC-3) | user enumeration | Login for unknown user performs dummy Argon2 (constant-ish time) | source assertion | read `axiam-auth` service.rs not-found path | ✅ | ⬜ pending |
| 11-03 | 3 | REQ-15 (AC-3) | TOCTOU | `record_failed_login` uses SurrealQL atomic `+= 1` UPDATE | source assertion | read user repo method | ✅ | ⬜ pending |
| 11-03 | 3 | REQ-15 (AC-3) | CSRF | POST to `/api/v1` CRUD without `X-CSRF-Token` → 403 | integration | `cargo test -p axiam-api-rest --test csrf_crud_test` | ❌ W0 | ⬜ pending |
| 11-03 | 3 | REQ-15 (AC-3) | weak reset | Change/reset password to current → 400 (`PasswordReusedCurrent`) | unit | `cargo test -p axiam-auth -- change_password` | ✅ | ⬜ pending |
| 11-03 | 3 | REQ-15 (AC-3) | authz bypass | Permission enforced via `ROUTE_PERMISSION_MAP`; bootstrap transactional + gated | integration | `cargo test -p axiam-api-rest --test integration` | ✅ | ⬜ pending |
| 11-03 | 3 | REQ-15 (AC-3) | priv-esc | self-update strips `status` + gates email change; logout revokes caller's own session | integration | `cargo test -p axiam-api-rest --test integration` | ✅ | ⬜ pending |
| 11-04 | 4 | REQ-15 (AC-4) | misconfig | k8s configmap keys use `AXIAM__` prefix; secrets via Secret | source assertion | read `k8s/server/configmap.yml` | ✅ | ⬜ pending |
| 11-04 | 4 | REQ-15 (AC-4) | exposure | PSA `restricted` enforce label; receiver-side NetworkPolicies; backend ports unpublished | source assertion | read `k8s/namespace.yml`, network policies | ✅ | ⬜ pending |
| 11-04 | 4 | REQ-15 (AC-4) | default creds | prod compose has no literal default creds; `/oauth2/*` + `/.well-known` proxied | source assertion | read `docker-compose.prod.yml`, nginx conf | ✅ | ⬜ pending |
| 11-05 | 5 | REQ-15 (AC-5) | UX/error leak | All mutations show toast via `getApiErrorMessage`; form validation present | unit + manual | `cd frontend && npm test -- apiError` + browser smoke | ❌ W0 (apiError.test.ts) | ⬜ pending |
| 11-05 | 5 | REQ-15 (AC-5) | authz UX | Route guards render friendly 403; login handles `mfa_setup_required`/`mfa_required` | manual smoke | `just dev-up` + browser | ✅ | ⬜ pending |
| 11-05 | 5 | REQ-15 (AC-5) | data integrity | Resource parent picker excludes descendants; federation edit locks type; pagination `placeholderData` | source assertion + manual | read components | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `crates/axiam-db/src/helpers.rs` — does not exist yet; created by Plan 11-01 (shared repo helpers + 409 mapping)
- [ ] `crates/axiam-pki/tests/mtls_chain_test.rs` — does not exist; created by Plan 11-02 (SEC-024 chain verify, self-signed test CA + leaf)
- [ ] `crates/axiam-api-rest/tests/csrf_crud_test.rs` — extend existing CSRF tests to cover `/api/v1` scope (Plan 11-03)
- [ ] `crates/axiam-api-rest/src/.../webhook_ssrf` unit coverage — SSRF re-resolve+pin test (Plan 11-02)
- [ ] `frontend/src/lib/apiError.test.ts` — does not exist; vitest coverage for `getApiErrorMessage` (Plan 11-05)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Route guard → friendly ForbiddenPage | REQ-15 (AC-5) | Requires live session + router navigation | `just dev-up`; log in as low-privilege user; navigate to `/users`; assert ForbiddenPage with friendly 403 message |
| Login MFA branching | REQ-15 (AC-5) | Requires backend MFA state responses | `just dev-up`; trigger login returning `mfa_setup_required` then `mfa_required`; assert correct UI flow |
| tenant/org slug restore on reload | REQ-15 (AC-5) | SPA hydration from `/auth/me` | Browser hard-reload an authed page; assert sidebar/routes use correct tenant slug |
| dummy-Argon2 timing parity | REQ-15 (AC-3) | Timing-side-channel proof is environment-sensitive | Source assertion is primary proof; optional manual timing comparison of known-vs-unknown user login latency |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references (helpers.rs, mtls_chain_test.rs, csrf_crud_test.rs, apiError.test.ts)
- [ ] No watch-mode flags (no `cargo watch`, no `vitest --watch`)
- [ ] Feedback latency < 180s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

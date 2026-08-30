---
phase: 28
slug: functional-completeness
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-05
---

# Phase 28 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test` (Rust; unit `#[cfg(test)]` + `tests/*.rs` integration) |
| **Config file** | none — workspace `Cargo.toml` per crate |
| **Quick run command** | `cargo test -p <crate> --lib` |
| **Full suite command** | `cargo test -p axiam-api-rest -p axiam-auth -p axiam-amqp -p axiam-db --lib --tests` |
| **Estimated runtime** | ~120–300 seconds (crate-scoped) |

> **Build note:** any build/test of `axiam-api-rest` (or dependents) MUST first
> `export SWAGGER_UI_DOWNLOAD_URL=file:///home/user/.axiam-build-cache/swagger-ui-5.17.14.zip`
> (proxy blocks the GitHub swagger-ui download). `cargo clean` only *between* plans, never mid-run.

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p <crate> --lib`
- **After every plan wave:** Run the full suite command (crate-scoped)
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 300 seconds

---

## Per-Task Verification Map

> Populated by the planner from PLAN.md tasks. Each row maps a task to its automated verification.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 28-01-01 | 01 | 1 | FUNC-0X | T-28-0X / — | {expected secure behavior or "N/A"} | integration | `cargo test -p <crate> --test <name>` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `crates/axiam-api-rest/tests/*.rs` — new e2e for first-time federation login (FUNC-01, closes CQ-B40)
- [ ] `crates/axiam-api-rest/tests/*.rs` — email-config admin CRUD RBAC tests (FUNC-03)
- [ ] `crates/axiam-auth/src/token.rs` `#[cfg(test)]` — `sub_kind` on each mint path (FUNC-04)

*Existing infrastructure covers FUNC-02 (`password_reset_revokes_sessions.rs` already present) and FUNC-05 (OpenAPI parity test).*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| — | — | — | — |

*All phase behaviors target automated verification (unit/integration).*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 300s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

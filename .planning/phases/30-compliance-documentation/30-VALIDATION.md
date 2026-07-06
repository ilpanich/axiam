---
phase: 30
slug: compliance-documentation
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-06
---

# Phase 30 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Derived from `30-RESEARCH.md` § Validation Architecture. This is a
> **verify + document** phase — CMPL-02 is fully covered by existing Rust
> tests; the net-new validation surface is docs-lint (spec-validate +
> internal-link-check) over the new documentation artifacts.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test` (existing Rust integration tests) + net-new docs-lint (spec-validate + internal-link-check). No new test framework. |
| **Config file** | none new — existing workspace `Cargo.toml`; new `.github/workflows/docs-ci.yml` for docs-lint |
| **Quick run command** | `cargo test -p axiam-api-rest --test gdpr_test` (re-run existing GDPR evidence) |
| **Full suite command** | docs-CI job (spec-validate + link-check) + `cargo test -p axiam-api-rest --test gdpr_test`; `cargo test --workspace` only if a genuine CMPL-02 code gap is found |
| **Estimated runtime** | ~30–90s (docs-lint is near-instant; gdpr_test is the dominant cost) |

> Build/disk hygiene: scope cargo to `-p axiam-api-rest --test gdpr_test`; export
> `SWAGGER_UI_DOWNLOAD_URL=file:///home/user/.axiam-build-cache/swagger-ui-5.17.14.zip`
> before any `axiam-api-rest` build/test (per CLAUDE.md).

---

## Sampling Rate

- **After every task commit:** doc changes → run the internal-link-check script over touched docs; code changes (only if a real CMPL-02 gap) → run the specific `gdpr_test` case.
- **After every plan wave:** `cargo test -p axiam-api-rest --test gdpr_test` (full file) + full docs-CI job (spec-validate + link-check) locally.
- **Before `/gsd-verify-work`:** docs-CI job green in CI + unaffected `ci.yml` build/clippy/test (this phase should not touch non-docs Rust code).
- **Max feedback latency:** ~90 seconds.

---

## Per-Task Verification Map

> Completed by the planner against real PLAN task IDs. Requirement→evidence
> mapping below is fixed by research; the planner binds each row to its task.

| Requirement | Behavior | Test Type | Automated Command | File Exists |
|-------------|----------|-----------|-------------------|-------------|
| CMPL-02 | Export blob includes real sessions | integration (existing) | `cargo test -p axiam-api-rest --test gdpr_test export_includes_real_session_metadata` | ✅ exists |
| CMPL-02 | Export includes consents / every table | integration (existing) | `cargo test -p axiam-api-rest --test gdpr_test export_completeness` | ✅ exists |
| CMPL-02 | Erasure durably pseudonymizes audit PII | integration (existing) | `cargo test -p axiam-api-rest --test gdpr_test deletion_pseudonymization` | ✅ exists |
| CMPL-02 | Consent recorded at registration | integration (existing) | `cargo test -p axiam-api-rest --test gdpr_test consent_on_registration` | ✅ exists |
| DOCS-01 | OpenAPI JSON parses | docs-lint | `jq empty docs/api/openapi.json` (or reuse `sdk-openapi-drift.yml`) | ✅ mechanism exists |
| DOCS-01 | AsyncAPI spec validates | docs-lint | `npx @asyncapi/cli validate docs/api/asyncapi.yml` | ❌ W0 (spec is net-new) |
| DOCS-01 / CMPL-01 | Every internal doc link resolves | docs-lint | `<link-check script> docs/**/*.md claude_dev/security-audit.md` | ❌ W0 (script net-new) |
| CMPL-01 | `security-audit.md` open items cross-ref v1.2 REQ-IDs | docs-lint (grep) | `grep -E "REQ-\|SEC(FIX\|HRD)-\|CMPL-\|DOCS-" claude_dev/security-audit.md` | ❌ W0 |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `docs/api/asyncapi.yml` — net-new AsyncAPI 2.6 spec (feeds the AsyncAPI-validate check)
- [ ] Internal-link-check script (project `scripts/` convention; zero-dependency preferred over `markdown-link-check`) — covers 3 DOCS-01/CMPL-01 rows
- [ ] `.github/workflows/docs-ci.yml` — path-filtered CI job wiring spec-validate + link-check
- [ ] `claude_dev/security-audit.md` — net-new master doc (links/REQ-IDs are lint-checked; content correctness is human review per D-03)

*CMPL-02 has no Wave 0 gaps — existing `gdpr_test.rs` fully covers its assertions.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| ISO 27001 Annex A family + CyberSecurity Act theme mappings are correct | CMPL-01 | No canonical crosswalk exists; mapping is interpretive (RESEARCH Assumptions A1/A2, flagged `[ASSUMED]`) | Reviewer confirms each family/theme→evidence-pointer row is defensible; confirm "CyberSecurity Act" interpretation (EU CRA vs 2019/881) |
| `security-audit.md` does not overclaim compliance status | CMPL-01 | Documentation-integrity, not automatable | Reviewer confirms self-assessment framing + v1.2/beta + last-verified stamp (D-12); spot-check a sample of pass rows against cited evidence (D-03) |
| GDPR doc accurately reconciles async export vs. roadmap `GET /users/:id/export` shorthand | CMPL-02 | Narrative correctness | Reviewer confirms D-05 reconciliation is stated honestly |

---

## Validation Sign-Off

- [ ] All net-new doc artifacts have a docs-lint automated check or explicit Manual-Only entry
- [ ] Sampling continuity: no wave without either a `gdpr_test` re-run or a docs-lint run
- [ ] Wave 0 covers all ❌ MISSING references (asyncapi.yml, link-check script, docs-ci.yml, security-audit.md)
- [ ] No watch-mode flags
- [ ] Feedback latency < 90s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

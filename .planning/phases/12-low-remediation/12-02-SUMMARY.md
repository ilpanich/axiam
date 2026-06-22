---
phase: 12-low-remediation
plan: "02"
subsystem: axiam-db, ci-cd, docs
tags: [security, sec-043, sec-040, sec-057, mfa-redaction, rbac-docs, sha-pinning]
dependency_graph:
  requires: []
  provides: [SEC-043-mfa-redact, SEC-040-rbac-docs, SEC-057-sha-pins]
  affects: [axiam-db, .github/workflows, CLAUDE.md, design-document.md]
tech_stack:
  added: []
  patterns: [custom-debug-redaction, explicit-column-projection, sha-pinned-actions]
key_files:
  created: []
  modified:
    - crates/axiam-db/src/repository/user.rs
    - claude_dev/design-document.md
    - CLAUDE.md
    - .github/workflows/ci.yml
    - .github/workflows/release.yml
decisions:
  - SEC-040 resolved as documentation correction only — engine.rs not modified; deny-override cascade deferred to post-v1.0-beta
  - SEC-043 UserRowWithId loses mfa_secret/totp_last_used_step fields entirely; try_into_user sets them to None (list path never hydrates ciphertext)
  - SEC-043 get_by_username and get_by_email also use UserRowWithId — SELECT * queries still work correctly (extra columns ignored by deserializer; mfa_secret absent from struct)
  - SEC-057 PATTERNS.md SHA table had errors for several docker actions; all SHAs verified via GitHub API before committing
metrics:
  duration: "10m"
  completed_date: "2026-06-19"
  tasks_completed: 3
  files_modified: 5
---

# Phase 12 Plan 02: SEC-043/SEC-040/SEC-057 Security Polish Summary

Closed three LOW security findings: SEC-043 (MFA ciphertext redaction), SEC-040 (RBAC docs accuracy), SEC-057 (GitHub Actions supply-chain pinning).

## Tasks

### Task 1: SEC-043 — mfa_secret redaction in Debug + list projection (commit: 2fc8ed7)

**Files:** `crates/axiam-db/src/repository/user.rs`

- Removed `Debug` derive from `UserRow` and `UserRowWithId`; added manual `impl std::fmt::Debug` for each that renders `mfa_secret` and `totp_last_used_step` as `"[REDACTED]"` via `.as_ref().map(|_| "[REDACTED]")` pattern with `.finish_non_exhaustive()`
- Removed `mfa_secret: Option<String>` and `totp_last_used_step: Option<u64>` fields from `UserRowWithId` (list-path struct); `try_into_user` sets both to `None` explicitly with a SEC-043 comment
- Replaced `SELECT meta::id(id) AS record_id, * FROM user ...` list query with explicit column projection that excludes `mfa_secret` and `totp_last_used_step`
- `UserRow` (used by `get_by_id`) retains both sensitive fields so MFA verification paths continue to function
- `cargo check -p axiam-db --tests --no-default-features` clean; `cargo test -p axiam-db --lib --no-default-features` 14 pass, 5 fail (pre-existing email_config tests — DB connectivity issue unrelated to user.rs)

### Task 2: SEC-040 — correct RBAC docs to additive-only (commit: 76cfec4)

**Files:** `claude_dev/design-document.md`, `CLAUDE.md`

**Scope: DOCUMENTATION CORRECTION ONLY. engine.rs was not modified.**

- Removed false "unless an explicit deny exists at a lower level" clause from design-document.md line 385
- Replaced with accurate wording: "additive-only, allow-wins; there is no explicit deny-override mechanism in v1.0-beta; deny-override cascade is deferred to post-v1.0-beta"
- Added RBAC additive-only note to `CLAUDE.md` under Authentication & Authorization Protocols section
- Deny-override cascade (new DenyPermission model + migration + engine rewrite) is explicitly deferred to post-v1.0-beta. This is a LOW finding and a doc fix is the correct resolution for v1.0-beta per the plan objective

### Task 3: SEC-057 — pin all GitHub Actions to commit SHAs (commit: db8bbea)

**Files:** `.github/workflows/ci.yml`, `.github/workflows/release.yml`

- Pinned all 19 `uses:` references across both workflows to verified 40-character commit SHAs
- Each SHA was verified via GitHub API (`gh api repos/<owner>/<action>/git/ref/tags/<tag>`) before committing — tag objects were dereferenced to commit SHAs
- **Deviation (Rule 1 — auto-fixed):** PATTERNS.md SHA table had errors for several actions (docker/setup-buildx-action, docker/metadata-action, docker/build-push-action, hadolint/hadolint-action, Swatinem/rust-cache). Used verified GitHub API SHAs instead
- `hadolint no-fail: true` and `trivy exit-code: '0'`/`'1'` advisory settings left unchanged
- Trailing `# <tag>` comment on every pinned line for future auditability

Actions pinned in ci.yml: actions/checkout@v4.2.2, dtolnay/rust-toolchain@stable(2026-03-27), Swatinem/rust-cache@v2.7.8, actions-rust-lang/audit@v1, EmbarkStudios/cargo-deny-action@v2, hadolint/hadolint-action@v3.1.0, aquasecurity/trivy-action@v0.36.0, github/codeql-action/upload-sarif@v4, actions/setup-node@v4, actions/upload-artifact@v4

Actions pinned in release.yml: (above) + docker/setup-buildx-action@v3.10.0, docker/login-action@v3.4.0, docker/metadata-action@v5.7.0, docker/build-push-action@v6.15.0, sigstore/cosign-installer@v3.8.1, actions/attest-build-provenance@v2, actions/download-artifact@v4, orhun/git-cliff-action@v4, softprops/action-gh-release@v2

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] PATTERNS.md SHA table had incorrect SHAs for several docker actions and hadolint**
- **Found during:** Task 3 (SHA verification via GitHub API)
- **Issue:** PATTERNS.md listed incorrect commit SHAs for docker/setup-buildx-action (`6524bf65...` vs actual `b5ca5143...`), docker/metadata-action (`902fa8ec...f9` vs actual `...04`), docker/build-push-action (`14487ce6...` vs actual `471d1dc4...`), hadolint/hadolint-action (`54c9adbab1582c2ef04b2016b760714a4a0bee3e` vs actual `54c9adbab1582c2ef04b2016b760714a4bfde3cf`), Swatinem/rust-cache (`82a92a6e...` vs actual `9d47c6ad...`)
- **Fix:** Used GitHub API verified SHAs for all 19 actions rather than trusting the PATTERNS.md table
- **Files modified:** `.github/workflows/ci.yml`, `.github/workflows/release.yml`

## Decisions Made

1. **SEC-040 doc-only fix (not engine rewrite):** Removed false "explicit deny" claim from design docs and CLAUDE.md. Deny-override cascade is a feature, not a LOW-priority bug fix — deferred to post-v1.0-beta per plan objective and PLAN.md explicit NOTE.

2. **UserRowWithId field removal over Optional:** Removed `mfa_secret` and `totp_last_used_step` from `UserRowWithId` entirely (rather than keeping them Optional) — this is cleaner and ensures the compiler enforces the invariant that list paths can never access these fields.

3. **get_by_username/email also benefit from SEC-043:** These point-lookup queries still use `SELECT *` but via `UserRowWithId` (which no longer has sensitive fields) — the DB returns the columns but they're dropped at deserialization. This is correct — those paths don't need mfa_secret.

## Known Stubs

None — all changes are security hardening with no placeholder data.

## Threat Flags

None — no new trust boundaries introduced. Changes reduce the existing threat surface (T-12-05, T-12-06, T-12-07, T-12-08 all mitigated).

## Self-Check: PASSED

Files exist:
- crates/axiam-db/src/repository/user.rs: FOUND
- claude_dev/design-document.md: FOUND
- CLAUDE.md: FOUND
- .github/workflows/ci.yml: FOUND
- .github/workflows/release.yml: FOUND

Commits exist:
- 2fc8ed7: FOUND (SEC-043)
- 76cfec4: FOUND (SEC-040)
- db8bbea: FOUND (SEC-057)

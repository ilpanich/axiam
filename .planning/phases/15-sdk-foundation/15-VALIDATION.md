---
phase: 15
slug: sdk-foundation
status: approved
nyquist_compliant: true
wave_0_complete: true
created: 2026-06-29
---

# Phase 15 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test` (Rust workspace) + shell/CI assertions (buf, OpenAPI drift, scaffold) |
| **Config file** | none — Cargo workspace; CI gates under `.github/workflows/` |
| **Quick run command** | `cargo test -p axiam-api-rest --no-default-features authz_check` |
| **Full suite command** | `cargo test -p axiam-api-rest --no-default-features` (targeted; see constraint below) |
| **Estimated runtime** | ~60–120 seconds (single crate) |

> **Disk/build constraint (project memory):** /home is near-full and the workspace `target/` is large — NEVER run a full-workspace `cargo test` / `just test`; link steps hit `os error 28` and surface as false code defects. Always scope with `-p <crate>` and targeted `--test`. Verify cargo by reading actual output text, not exit code (rtk masks it). Add `--no-default-features` so SAML/xmlsec off-path crates compile locally on Arch.

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p axiam-api-rest --no-default-features authz_check`
- **After every plan wave:** Run the relevant targeted suite (`-p` scoped) for crates touched in the wave
- **Before `/gsd:verify-work`:** Targeted suites green + CI gates (drift, buf lint/breaking, scaffold) pass
- **Max feedback latency:** ~120 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 15-01-01 | 01 | 1 | FND-04 | T-15-01 | `authz:check_as` permission registered + dedicated rate-limit tier (`authz_check_per_min: 300`), no global ceiling raise | source/unit | `grep -c 'authz:check_as' permissions.rs` + `grep 'authz_check_per_min: 300' rate_limit.rs` + `cargo check -p axiam-api-rest --no-default-features` | ✅ | ⬜ pending |
| 15-01-02 | 01 | 1 | FND-04 | T-15-01 | Cross-subject override requires `authz:check_as` (403 otherwise, no engine call); cross-subject query audited (`action="authz.check_as"`) | unit (tdd) | `cargo check -p axiam-api-rest --no-default-features` | ✅ | ⬜ pending |
| 15-01-03 | 01 | 1 | FND-04 | T-15-03 | Routes wrapped in dedicated governor; both routes in OpenAPI + parity test | integration (tdd) | `cargo test -p axiam-api-rest --no-default-features authz_check` + `... every_openapi_path_is_registered` | ✅ | ⬜ pending |
| 15-02-01 | 02 | 2 | FND-01 | T-15-04 | `--dump-openapi` exits before SurrealDB/AMQP init (proven with bogus DB URL) | ci/behavior | `cargo build -p axiam-server --no-default-features` + `AXIAM__DB__URL=ws://127.0.0.1:9 axiam-server --dump-openapi` | ✅ | ⬜ pending |
| 15-02-02 | 02 | 2 | FND-01 | T-15-04 | Committed spec deterministic (`--no-default-features` pinned); drift gate diff-clean | ci | `diff sdks/openapi.json <(axiam-server --dump-openapi)` + drift workflow `paths:` filter | ✅ | ⬜ pending |
| 15-03-01 | 03 | 1 | FND-03 | — | CONTRACT.md §1–§10 present incl. `Sensitive`, `HMAC-SHA256`, TLS CA | ci/source | `for s in 1..10: grep "§$s" sdks/CONTRACT.md` + `Sensitive`/`HMAC-SHA256`/`with_custom_ca` | ✅ | ⬜ pending |
| 15-03-02 | 03 | 1 | FND-03 | — | D-13 ROADMAP Go strings corrected (no stale `axiam-go-sdk` / `sdk/go/v`) | ci/source | `! grep 'axiam/axiam-go-sdk' ROADMAP.md` + `grep 'github.com/axiam/axiam/sdks/go'` | ✅ | ⬜ pending |
| 15-04-01 | 04 | 1 | FND-02 | — | `buf.yaml` v2 targets `../proto`; generated stubs gitignored (not committed) | ci | `grep 'version: v2' sdks/buf.yaml` + `grep '../proto'` + `.gitignore` stub paths | ✅ | ⬜ pending |
| 15-04-03 | 04 | 1 | FND-02 | — | `buf.gen.yaml` v2, no C# plugin (Grpc.Tools exception); buf lint+breaking CI on `proto/**` | ci | `grep 'version: v2' sdks/buf.gen.yaml` + `! grep csharp` + buf-gates workflow `breaking` | ✅ | ⬜ pending |
| 15-05-01 | 05 | 1 | FND-05 | — | All 7 `sdks/<lang>/LICENSE` present and Apache-2.0 | ci | `for l in 7 langs: test -f sdks/$l/LICENSE && grep 'Apache License'` | ✅ | ⬜ pending |
| 15-05-02 | 05 | 1 | FND-05 | — | Locked package identities in manifests; every README references CONTRACT.md | ci/source | `grep 'axiam-sdk'/'io.axiam'/'Axiam.Sdk'/'github.com/axiam/axiam/sdks/go'` + README CONTRACT ref | ✅ | ⬜ pending |
| 15-05-03 | 05 | 1 | FND-05 | — | 7 per-SDK CI workflows path-filtered to `sdks/<lang>/`, SHA-pinned checkout, no `libxmlsec1-dev` | ci | `for l: test -f sdk-ci-$l.yml && grep "sdks/$l/" && grep <pinned-sha>` + `! grep libxmlsec1-dev` | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

*All 12 `auto` tasks carry `<automated>` verify commands (above). The 2 `checkpoint:human-verify` tasks (15-04 Task 2 — buf Rust plugin BSR names; 15-06 Task 1 — registry/org name availability) are exempt from automated verification and tracked under Manual-Only Verifications below. FND-01/02/05 verify via shell/CI assertions; FND-04 via `cargo test -p axiam-api-rest`; FND-03 via section/grep assertions. "File Exists" = ✅ because no Wave 0 stubs are required — the parity-test extension (Wave 0 candidate) is handled inline in 15-01 Task 3.*

---

## Wave 0 Requirements

- [x] Extend `crates/axiam-api-rest/src/tests/route_openapi_parity_test.rs` to cover `/api/v1/authz/check` + `/check/batch` (FND-04) — handled inline in Plan 15-01 Task 3, not a separate Wave 0 task
- [x] `cargo test -p axiam-api-rest` framework already present — no install needed

*Existing Rust + CI infrastructure covers all phase requirements; no new test framework install required. `wave_0_complete: true` — the only Wave 0 candidate (parity-test extension) is satisfied within 15-01 T3.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| GitHub org `axiam` + 7 registry package-name availability (crates/npm/PyPI/Maven/NuGet/Packagist) | FND-05 / D-11–D-12 | External registries; cannot assume availability, no API auto-reserve in CI | Manually query each registry for `axiam-sdk` / `io.axiam:axiam-sdk` / `Axiam.Sdk` / `axiam/axiam-sdk`; record reserved/squatted status; reserve before first publish |
| buf remote plugin names for Rust (`neoeinstein-prost`/`neoeinstein-tonic`) resolve on buf.build BSR | FND-02 | Plugin names [ASSUMED] in research — need live BSR check before committing `buf.gen.yaml` | Install buf, run `buf generate` from clean checkout; confirm stubs emit for all 5 buf-managed languages |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies (12 auto tasks verified; 2 human-verify checkpoints exempt)
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (none — parity test inline in 15-01 T3)
- [x] No watch-mode flags
- [x] Feedback latency < 120s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-06-29

---
phase: 15-sdk-foundation
plan: "02"
subsystem: server-binary, ci
tags: [openapi, sdk, ci, drift-gate, fnd-01]
dependency_graph:
  requires: [15-01]
  provides: [sdks/openapi.json, --dump-openapi flag, OpenAPI drift CI gate]
  affects: [sdks/, .github/workflows/sdk-openapi-drift.yml, crates/axiam-server]
tech_stack:
  added: []
  patterns: [early-exit-flag, openapi-export, github-actions-path-filter]
key_files:
  created:
    - sdks/openapi.json
    - .github/workflows/sdk-openapi-drift.yml
  modified:
    - crates/axiam-server/src/main.rs
decisions:
  - "--dump-openapi uses early-exit pattern identical to healthcheck; placed before tracing_subscriber::fmt() and load_config()"
  - "sdks/openapi.json generated with --no-default-features (SAML excluded) for deterministic output on any host"
  - "drift gate uses diff (not git diff --exit-code) to avoid needing git tracking of /tmp file"
  - "release-tag trigger (v*) and push-to-main trigger share the same push: block in YAML (combined to avoid duplicate-key YAML error)"
metrics:
  duration: "9 minutes"
  completed: "2026-06-30T09:47:53Z"
  tasks_completed: 2
  tasks_total: 2
  files_created: 2
  files_modified: 1
status: complete
---

# Phase 15 Plan 02: OpenAPI Export Flag & SDK Drift Gate Summary

One-liner: `--dump-openapi` early-exit in axiam-server prints the full OpenAPI 3.1.0 spec to stdout before any DB/AMQP init; `sdks/openapi.json` committed (includes both authz-check paths from Plan 15-01); CI drift gate blocks PRs on any spec divergence.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Add --dump-openapi early-exit branch to axiam-server | b7add97 | crates/axiam-server/src/main.rs |
| 2 | Generate & commit sdks/openapi.json and add drift-gate CI workflow | 220b0e2 | sdks/openapi.json, .github/workflows/sdk-openapi-drift.yml |

## Verification

All success criteria confirmed:

- `axiam-server --dump-openapi` exits 0 with bogus DB URL `ws://127.0.0.1:9` (no DB connection attempt)
- `--dump-openapi` branch is inserted after the healthcheck block (line 116) and before `tracing_subscriber::fmt()` (line 121) and before `load_config()`
- `sdks/openapi.json` is valid JSON (11 714 lines), contains `/api/v1/authz/check` and `/api/v1/authz/check/batch`
- `diff sdks/openapi.json <(axiam-server --dump-openapi)` is clean immediately after generation
- `.github/workflows/sdk-openapi-drift.yml` is path-filtered on `crates/axiam-api-rest/**` + `crates/axiam-server/**`; uses verbatim SHA-pinned actions from ci.yml; runs `--no-default-features`; does NOT install `libxmlsec1-dev`; fails on `diff`; includes release-tag trigger for D-04

## Implementation Notes

### Task 1: --dump-openapi early-exit

The flag uses the same pattern as the existing `healthcheck` early-exit block (main.rs:106-116). Inserted at main.rs:118-130 (new block), before `tracing_subscriber::fmt()` at line 131. Uses `axiam_api_rest::openapi::api_doc()` which is already a `pub fn` in a `pub mod`; `serde_json` is already a direct dep of `axiam-server` (Cargo.toml:39). Block is documented with the exact export command:

```bash
cargo build -p axiam-server --no-default-features
./target/debug/axiam-server --dump-openapi > sdks/openapi.json
```

### Task 2: sdks/openapi.json and drift gate

The spec was generated immediately after the Task 1 build. Both `/api/v1/authz/check` and `/api/v1/authz/check/batch` routes were present — confirming Plan 15-01 landed correctly.

The drift gate YAML uses a combined `push:` block with both `branches: [main]` with path filter and `tags: ['v*']` for the D-04 release-tag trigger. This avoids the YAML duplicate-key error that would occur with two separate `push:` entries at the same level.

CI job mirrors the `build-no-saml` job from `ci.yml` exactly: same three SHA-pinned actions, same `protobuf-compiler`-only install, no `libxmlsec1-dev`. The comment in the workflow explicitly explains the intentional absence of `libxmlsec1-dev` as a SAML-leak guard.

## Deviations from Plan

None — plan executed exactly as written.

The disk-space constraint (25G build artifacts, only 424MB free at start) required clearing old duplicate `.rlib` files and the `incremental/` cache directory before the build could succeed. These are derived artifacts, not source files, and their removal does not affect correctness.

## Threat Flag Check

No new network endpoints or auth paths introduced. The `--dump-openapi` output is the public `api_doc()` only (T-15-06: mitigated). SAML paths excluded via `--no-default-features` (T-15-07: mitigated). CI actions are SHA-pinned verbatim from ci.yml (T-15-SC: mitigated).

## Self-Check: PASSED

- `crates/axiam-server/src/main.rs` — modified (contains `--dump-openapi`)
- `sdks/openapi.json` — created (11714 lines, valid JSON, contains both authz paths)
- `.github/workflows/sdk-openapi-drift.yml` — created (path-filtered, SHA-pinned, feature-pinned)
- Commits b7add97 and 220b0e2 confirmed in git log

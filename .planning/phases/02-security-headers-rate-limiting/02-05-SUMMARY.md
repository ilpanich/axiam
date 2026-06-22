---
phase: 02-security-headers-rate-limiting
plan: "05"
subsystem: axiam-api-rest, axiam-auth
tags: [rate-limiting, lockout, security, gap-closure]
dependency_graph:
  requires: [02-04-PLAN.md]
  provides: [register-rate-limit-wired, lockout-default-corrected]
  affects: [axiam-api-rest, axiam-auth]
tech_stack:
  added: []
  patterns: [actix-web-resource-wrap, governor-rate-limit]
key_files:
  created: []
  modified:
    - crates/axiam-api-rest/src/server.rs
    - crates/axiam-auth/src/config.rs
decisions:
  - "Wrap entire /users resource with rate limiter (not just POST) — Actix-Web resource wrap applies to all methods; GET at 5 req/min is acceptable for admin list endpoint"
  - "lockout_duration_secs default changed from 300 to 900 to match REQ-3 (15-minute cooldown)"
metrics:
  duration: "~10 minutes"
  completed: "2026-04-08T20:49:46Z"
  tasks: 2
  files: 2
---

# Phase 02 Plan 05: Gap Closure — Register Rate Limit and Lockout Default Summary

Closed two verification gaps preventing Phase 02 from passing: wired `register_per_min` rate limiter to the `/users` resource, and corrected `lockout_duration_secs` default from 300 to 900 seconds (15 minutes per REQ-3).

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Wire register_per_min rate limiter to POST /api/v1/users | 845b2be | crates/axiam-api-rest/src/server.rs |
| 2 | Fix lockout cooldown default to 900 seconds (15 min) | 4baa4cd | crates/axiam-auth/src/config.rs |

## What Was Built

**Task 1 — Rate limiter wired to /users resource:**

Added `.wrap(build_governor(rate_limit_cfg.register_per_min))` to the `/users` web resource in `server.rs`. This follows the exact same pattern used for `/login`, `/reset`, and `/token` endpoints. The wrap applies to all HTTP methods on the resource (both POST and GET), which is correct Actix-Web behavior. GET at 5 req/min is acceptable for an admin list endpoint.

**Task 2 — Lockout duration corrected:**

Changed `lockout_duration_secs` default from 300 to 900 in `crates/axiam-auth/src/config.rs`. Updated both the field default value and the doc comment. REQ-3 specifies a 15-minute (900s) cooldown period. The environment variable `AXIAM__AUTH__LOCKOUT_DURATION_SECS` continues to override this at runtime.

## Verification Results

All four verification checks pass:
1. `cargo check -p axiam-api-rest` — passes
2. `cargo check -p axiam-auth` — passes
3. `grep "build_governor(rate_limit_cfg.register_per_min)" crates/axiam-api-rest/src/server.rs` — match found (line 201)
4. `grep "lockout_duration_secs: 900" crates/axiam-auth/src/config.rs` — match found (line 91)

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

None.

## Self-Check: PASSED

- `crates/axiam-api-rest/src/server.rs` — modified, contains `build_governor(rate_limit_cfg.register_per_min)` at line 201
- `crates/axiam-auth/src/config.rs` — modified, contains `lockout_duration_secs: 900`
- Commit 845b2be — verified present in git log
- Commit 4baa4cd — verified present in git log

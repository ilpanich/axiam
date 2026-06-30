---
phase: 15-sdk-foundation
plan: "03"
subsystem: sdks
status: complete
tags: [sdk, contract, documentation, d09, d10, d13, fnd-03]
dependency_graph:
  requires: []
  provides: [sdks/CONTRACT.md, D-09-binding-contract, D-10-locked-vocabulary]
  affects: [phase-16-rust-sdk, phase-17-typescript-sdk, phase-18-go-sdk, phase-19-python-sdk, phase-20-java-sdk, phase-21-csharp-sdk, phase-22-php-sdk]
tech_stack:
  added: []
  patterns: [cross-language-behavioral-contract, normative-binding-documentation]
key_files:
  created:
    - sdks/CONTRACT.md
  modified:
    - .planning/ROADMAP.md
decisions:
  - sdks/CONTRACT.md is normative/binding (D-09); Rust Phase 16 implements it, does not define it
  - Canonical method vocabulary locked: login/verify_mfa/refresh/logout/check_access/can/batch_check (D-10)
  - Error taxonomy locked: AuthError/AuthzError/NetworkError with HTTP+gRPC status tables
  - Go module path is github.com/axiam/axiam/sdks/go, tag sdks/go/vX.Y.Z (D-13 fixup applied)
  - C# Grpc.Tools is the one documented buf pipeline exception (D-01)
metrics:
  duration_min: 8
  completed_date: "2026-06-30"
  tasks_completed: 2
  files_changed: 2
---

# Phase 15 Plan 03: SDK CONTRACT.md + D-13 ROADMAP Fixup Summary

**One-liner:** Authored normative cross-language SDK behavioral contract (D-09) with all 10 sections, locked D-10 vocabulary, and applied D-13 Go module/tag fixup to ROADMAP Phase 18.

## What Was Built

### Task 1: `sdks/CONTRACT.md` (D-09 normative contract)

Created `sdks/CONTRACT.md` (306 lines) with 10 normative sections constituting the binding cross-language behavioral contract for all 7 AXIAM SDKs (Phases 16–22):

- **§1 Method naming map**: Per-language idiom table for all 7 canonical operations (login, verify_mfa, refresh, logout, check_access, can, batch_check). D-10 vocabulary locked here; Rust Phase 16 implements it, not defines it.
- **§2 Error taxonomy**: AuthError / AuthzError / NetworkError definitions, HTTP-status→error-type table, gRPC-status→error-type table.
- **§3 CSRF behavior**: Auto-forward X-CSRF-Token on POST/PUT/PATCH/DELETE; applies equally to browser and non-browser SDKs.
- **§4 Cookie-jar requirement**: Non-browser SDKs must initialize persistent cookie store; per-language guidance table.
- **§5 Tenant context contract**: tenant_slug/tenant_id is non-optional constructor parameter; injected as X-Tenant-ID on every HTTP request and x-tenant-id gRPC metadata.
- **§6 TLS policy**: Strict by default; `with_custom_ca(pem)` only escape hatch; no skip_tls_verification API (T-15-08 mitigated).
- **§7 Sensitive<T> requirement**: Token fields suppress Debug/Display/toString/__repr__; raw token never via public API (T-15-09 mitigated).
- **§8 AMQP HMAC contract**: HMAC-SHA256(secret, body) verified against hmac_signature; nack WITHOUT requeue on failure; references crates/axiam-amqp/src/messages.rs (T-15-10 mitigated).
- **§9 Single-flight refresh guard**: Exactly one in-flight refresh; concurrent 401s wait and reuse result; 401 on refresh → AuthError, no retry.
- **§10 Middleware/route-guard interface**: Per-framework table covering Actix extractor, Express/Fastify, FastAPI, Django, Spring, ASP.NET Core, net/http, Laravel/Symfony.

Closing notes include: conformance statement requirement for each SDK README, C# Grpc.Tools documented exception, OpenAPI feature-flag note.

### Task 2: D-13 ROADMAP Go module/tag fixup

Applied two targeted string replacements to `.planning/ROADMAP.md` Phase 18 Go SDK success criteria:

| Location | Before | After |
|----------|--------|-------|
| Line 669, success criterion #1 | `go get github.com/axiam/axiam-go-sdk` | `go get github.com/axiam/axiam/sdks/go` |
| Line 673, success criterion #5 | `sdk/go/vX.Y.Z` | `sdks/go/vX.Y.Z` |

No other ROADMAP content changed.

## Verification

Both automated verification commands passed:

```
CONTRACT_OK   (all 10 sections present; Sensitive, HMAC-SHA256, with_custom_ca verified)
FIXUP_OK      (no stale axiam-go-sdk or sdk/go/v strings; canonical strings present)
```

## Commits

| Task | Commit | Files | Message |
|------|--------|-------|---------|
| 1 | aa3738b | sdks/CONTRACT.md | docs(15-03): author sdks/CONTRACT.md — normative cross-language SDK contract (D-09) |
| 2 | 3326afb | .planning/ROADMAP.md | docs(15-03): apply D-13 ROADMAP Go module/tag fixup (Phase 18) |

## Deviations from Plan

None — plan executed exactly as written.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced. This plan creates documentation only.

## Known Stubs

None. CONTRACT.md is a complete normative document, not a stub.

## Self-Check: PASSED

- [x] `sdks/CONTRACT.md` exists (306 lines, > 80 minimum)
- [x] All 10 sections present (§1–§10)
- [x] `Sensitive` found in CONTRACT.md
- [x] `HMAC-SHA256` found in CONTRACT.md
- [x] `with_custom_ca` found in CONTRACT.md
- [x] `axiam/axiam-go-sdk` NOT in ROADMAP.md
- [x] `sdk/go/v` NOT in ROADMAP.md
- [x] `github.com/axiam/axiam/sdks/go` found in ROADMAP.md
- [x] `sdks/go/vX.Y.Z` found in ROADMAP.md
- [x] Both commits exist: aa3738b, 3326afb

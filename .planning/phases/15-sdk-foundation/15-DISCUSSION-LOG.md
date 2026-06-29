# Phase 15: SDK Foundation - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-29
**Phase:** 15-sdk-foundation
**Areas discussed:** Proto stub delivery, Drift-gate cadence, /authz/check surface, CONTRACT.md authority, Package/publish identities

---

## Proto Stub Delivery

| Option | Description | Selected |
|--------|-------------|----------|
| Vendor + no-diff gate | Commit generated stubs into each sdks/<lang>/; CI regenerates and fails on diff. No buf toolchain for consumers; published packages already contain stubs. | |
| Generate-on-build | No generated code in git; each SDK build + CI runs buf into a gitignored dir. Clean git; every contributor/CI needs buf; publish still bundles stubs. | ✓ |
| Hybrid (Rust generates, rest vendor) | Rust uses tonic-build/build.rs; the 5 registry languages vendor committed stubs + diff gate. | |

**User's choice:** Generate-on-build
**Notes:** Captured the consequence — registry consumers cannot run buf, so release/packaging must regenerate-and-bundle stubs; FND-02's single documented command doubles as the publish-time codegen step (CONTEXT D-01, D-02).

---

## Drift-Gate Cadence

| Option | Description | Selected |
|--------|-------------|----------|
| Every PR touching source | Path-filtered: OpenAPI gate on axiam-api-rest/** PRs; buf lint+breaking on proto/** PRs; release-tag re-export as confirm. | ✓ |
| Release-tag only | Gates run only at release tag (literal success criterion). Cheapest; drift accumulates silently until the cut. | |
| Every PR, but warn-only pre-release | Non-blocking PR drift report; hard-fail only at release tag. Visibility without blocking; warn-only gates get ignored. | |

**User's choice:** Every PR touching source (path-filtered) + release-tag confirm
**Notes:** (CONTEXT D-03, D-04)

---

## /authz/check Surface (3 sub-decisions)

### Batch endpoint

| Option | Description | Selected |
|--------|-------------|----------|
| Yes — add POST /authz/check/batch now | Mirror gRPC BatchCheckAccess; browser can() avoids N round-trips; uniform across all later SDKs. | ✓ |
| No — single-decision only | Defer batch; TS browser persona may need to reopen the contract later. | |

### Subject semantics

| Option | Description | Selected |
|--------|-------------|----------|
| Caller-only now; admin-override deferred | Subject is always the session identity. Simplest. | |
| Caller + admin subject-override now | Optional subject_id; requires admin permission; cross-subject query audited. | ✓ |

### Rate-limit tier

| Option | Description | Selected |
|--------|-------------|----------|
| Dedicated higher-limit tier | Own bucket, higher ceiling; reuses Phase-2 middleware. | ✓ |
| Reuse standard authenticated-endpoint limit | No new tier; risk of tripping on button-heavy pages. | |

**User's choice:** Batch=Yes; Subject=Caller + admin override; Rate limit=Dedicated tier
**Notes:** Admin-override needs a gating permission + audit entry — flagged as a research item against the permission registry (CONTEXT D-05..D-08, Discretion).

---

## CONTRACT.md Authority

| Option | Description | Selected |
|--------|-------------|----------|
| Binding + lock vocab now | Normative; conformance becomes a per-SDK-phase checklist; method-name map + error taxonomy locked in Phase 15. | ✓ |
| Binding, but vocab set by Rust first | Normative, but vocab ratified from the Rust reference (Phase 16) and back-filled. | |
| Advisory guidance | Documents intent; each SDK adapts; risks cross-language divergence the research warned of. | |

**User's choice:** Binding + lock vocab now
**Notes:** Rust (Phase 16) implements the contract, does not define it (CONTEXT D-09, D-10).

---

## Package / Publish Identities

### GitHub org / namespace base

| Option | Description | Selected |
|--------|-------------|----------|
| axiam | github.com/axiam, io.axiam, axiam/, Axiam.* — matches roadmap strings. | ✓ |
| Different org base | A different company namespace, propagated across all 7 identities. | |

### Go module path vs monorepo

| Option | Description | Selected |
|--------|-------------|----------|
| Monorepo subdir; fix roadmap string | sdks/go/, module github.com/axiam/axiam/sdks/go, tag sdks/go/vX.Y.Z; update Phase 18 strings. | ✓ |
| Vanity import path | go.axiam.dev/sdk via meta redirect; must host the redirect. | |
| Split-out Go repo | Dedicated github.com/axiam/axiam-go-sdk repo; matches go get verbatim; needs sync tooling. | |

**User's choice:** org=axiam; Go=monorepo subdir (roadmap Phase 18 strings need fixup)
**Notes:** Package names ratified as already written in roadmap success criteria (CONTEXT D-11..D-13).

---

## Claude's Discretion
- `--dump-openapi` internal code structure (subcommand vs early-return branch).
- gitignored generated-stub output directory naming.
- The specific permission name gating the admin subject-override (D-06) — research against the existing permission registry.

## Deferred Ideas
- Automated cross-language conformance test harness for CONTRACT.md.
- Go vanity import path (go.axiam.dev/sdk) — deferred in favor of plain monorepo subdir.
- Split-out per-SDK repos — considered and rejected; monorepo model stands.

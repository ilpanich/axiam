---
phase: 15-sdk-foundation
plan: 06
status: complete
requirements: [FND-05]
---

# 15-06 Summary — Package Identity & GitHub Org Verification (FND-05)

**Completed:** 2026-06-30
**Type:** human-verify checkpoint (de-risk FND-05 package identities before Phases 16–22 build publish pipelines)

## What was verified

Availability checked via each registry's authoritative API (`404` = available, `200` = taken):

| Identity | Registry | Status |
|----------|----------|--------|
| `axiam-sdk` | crates.io | ✅ AVAILABLE |
| `axiam-sdk` | npm | ✅ AVAILABLE |
| `axiam-sdk` | PyPI | ✅ AVAILABLE |
| `io.axiam:axiam-sdk` | Maven Central | ✅ AVAILABLE (artifact free; `io.axiam` Sonatype namespace ownership is a separate publish-time gate) |
| `Axiam.Sdk` | NuGet | ✅ AVAILABLE |
| `axiam/axiam-sdk` | Packagist | ✅ AVAILABLE |
| `github.com/axiam` (org) | GitHub | ⚠️ TAKEN — existing **user** account (created 2020-11-13, 0 public repos) |

## Decision (operator, 2026-06-30)

`github.com/axiam` is an existing, unrelated user account. GitHub users and orgs share one
namespace, so an `axiam` org cannot be created while that user exists. The project's actual
home is **`github.com/ilpanich/axiam`**.

**Decision: host the SDKs in the existing `ilpanich/axiam` monorepo.**
Canonical Go module path: **`github.com/ilpanich/axiam/sdks/go`** (version-tag prefix
`sdks/go/vX.Y.Z` unchanged — Go monorepo subdir convention). This supersedes the D-13
placeholder `github.com/axiam/axiam/sdks/go`.

## Changes applied (this plan)
- `sdks/go/go.mod` → `module github.com/ilpanich/axiam/sdks/go`
- `sdks/go/README.md` → install/import strings repointed (3 references)
- `.planning/ROADMAP.md` Phase 18 → `go get github.com/ilpanich/axiam/sdks/go`
- `.planning/phases/15-sdk-foundation/15-VALIDATION.md` → check strings repointed

## Package-name fallbacks
None required — all 7 registry identities are available and retained as-is (D-11/D-12).

## Residual items (carry to Phase 18 / Go SDK)
- `.planning/REQUIREMENTS.md` and `.planning/research/STACK.md` still carry the pre-D-13
  `github.com/axiam/axiam-go-sdk` form (historical research/requirements notes) — reconcile
  when Phase 18 builds the Go publish pipeline.
- The registry names are available but **unreserved**; reserve them before Phases 16–22
  publish pipelines go live.
- buf.build BSR was unreachable from the build sandbox; buf plugin names were verified against
  the canonical `github.com/bufbuild/plugins` source repo instead (recorded in 15-04).

## Self-Check: PASSED
All 7 registry identities checked via API; GitHub namespace resolved (`axiam` taken → host under
`ilpanich/axiam`); operator decision recorded and applied to go.mod / README / ROADMAP / VALIDATION.

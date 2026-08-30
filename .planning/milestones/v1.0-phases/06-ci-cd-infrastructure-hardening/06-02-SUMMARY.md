---
phase: 06-ci-cd-infrastructure-hardening
plan: "02"
subsystem: ci-cd
tags: [trivy, container-scan, cosign, release, sarif, security-events]
dependency_graph:
  requires: ["06-03"]
  provides: ["container-image-scan-gate", "sarif-security-tab-images"]
  affects: [".github/workflows/release.yml"]
tech_stack:
  added:
    - "aquasecurity/trivy-action@v0.36.0 (image scan)"
    - "github/codeql-action/upload-sarif@v4 (SARIF upload)"
  patterns:
    - "load:true → trivy image → push:true with GHA cache (digest-consistent)"
    - "per-job permissions override (security-events: write)"
key_files:
  modified:
    - ".github/workflows/release.yml"
decisions:
  - "trivy-action pinned at v0.36.0 — confirmed current at github.com/aquasecurity/trivy-action/releases (2026-06-04)"
  - "GHA cache (type=gha) used on both build steps to guarantee scanned digest == pushed digest (Pitfall 2)"
  - "Top-level workflow permissions retained; image jobs add per-job override for security-events:write (least privilege)"
metrics:
  duration: "~5 minutes"
  completed_date: "2026-06-04"
  tasks_completed: 1
  files_modified: 1
---

# Phase 6 Plan 2: Release Image Scan Gate Summary

**One-liner:** Trivy image gate blocks HIGH/CRITICAL unfixed CVEs before cosign signs and publishes, using load→scan→push with GHA cache for digest consistency.

## What Was Built

Reordered `.github/workflows/release.yml` for both `build-server` and `build-frontend` jobs from a single build-push step to a three-step sequence:

1. **Build local** (`load: true`, `cache-from/to: type=gha`) — loads image into Docker daemon under `axiam-{server,frontend}:scan-${{ github.sha }}`
2. **Trivy image scan** (`aquasecurity/trivy-action@v0.36.0`) — scans the local image, `severity: HIGH,CRITICAL`, `ignore-unfixed: true`, `exit-code: 1` (blocks release); SARIF output uploaded to GitHub Security tab via `github/codeql-action/upload-sarif@v4` with `if: always()` and distinct categories (`trivy-image-server` / `trivy-image-frontend`)
3. **Push** (`push: true`, `cache-from: type=gha`) — reuses GHA cache from Step 1, producing the same manifest digest

Cosign sign and attest-build-provenance steps follow the push step, signing `${{ steps.build.outputs.digest }}` (the pushed digest, identical to the scanned one via GHA cache).

`security-events: write` added to per-job `permissions:` blocks on both image jobs.

## Decisions Made

- **trivy-action version:** `v0.36.0` — confirmed current at `github.com/aquasecurity/trivy-action/releases` on 2026-06-04. Research had flagged this as `[ASSUMED]`; now verified.
- **Digest consistency:** Both `load:true` and `push:true` steps use `cache-from: type=gha`. The build-local step additionally uses `cache-to: type=gha,mode=max` to prime the cache. Same job, back-to-back steps, same Dockerfile/context, same cache → same layers → same manifest digest. Mitigates Research Pitfall 2.
- **Per-job permissions:** Added `security-events: write` only to `build-server` and `build-frontend` jobs (via per-job `permissions:` block), not to `build-binary` or `release` jobs. Least-privilege: top-level workflow permissions remain as baseline for other jobs.
- **`if: always()` on SARIF upload:** Ensures scan findings reach the Security tab even when the scan step exits 1 (blocking), so developers can see what CVEs caused the block.

## Deviations from Plan

None — plan executed exactly as written.

## Threat Coverage

| Threat ID | Mitigation | Status |
|-----------|-----------|--------|
| T-06-05 | trivy image scan blocks HIGH/CRITICAL fixable before push + cosign sign | Implemented |
| T-06-06 | cosign signs exact pushed digest; GHA cache guarantees scanned==pushed | Implemented |
| T-06-07 | SARIF uploaded to GitHub Security tab (categories: trivy-image-server, trivy-image-frontend) | Implemented |
| T-06-08 | `--ignore-unfixed` skips CVEs with no upstream fix; distroless base (06-03) minimizes surface | Implemented |

## Known Stubs

None.

## Threat Flags

None — no new network endpoints, auth paths, or schema changes introduced. This plan only modifies CI pipeline configuration.

## Self-Check: PASSED

- `ff68bc7` exists in git log
- `.github/workflows/release.yml` modified: scan-type: image, exit-code: 1, upload-sarif@v4, cosign sign, security-events: write all present
- `load: true` step precedes trivy scan; `push: true` step follows it
- Both build steps use `cache-from: type=gha`; attest-build-provenance retained

## Checkpoint

Plan 06-02 stopped at `checkpoint:human-verify` — live CI validation required (tag push to confirm build→scan→push→sign sequence; SARIF in Security tab; scanned digest == signed digest).
